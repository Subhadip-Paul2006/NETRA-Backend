//! Windows native Win32 IP Helper routing table collector.

#[cfg(windows)]
use netra_core::error::{NetraError, Result};
#[cfg(windows)]
use netra_core::observation::{
    ObservationPayload, RouteObservationPayload, RouteRecord, RouteType,
};
#[cfg(windows)]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(windows)]
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToAlias, FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2,
};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

/// Collects the current host routing table from the Windows kernel via `GetIpForwardTable2`.
#[cfg(windows)]
pub fn collect_windows_routes() -> Result<ObservationPayload> {
    let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();

    // SAFETY: GetIpForwardTable2 allocates and returns a pointer to MIB_IPFORWARD_TABLE2.
    // Memory is freed unconditionally at the end of this scope via FreeMibTable.
    let ret = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table_ptr) };

    if ret != ERROR_SUCCESS || table_ptr.is_null() {
        return Err(NetraError::platform(format!(
            "GetIpForwardTable2 failed with Win32 error code {}",
            ret
        )));
    }

    let mut routes = Vec::new();

    unsafe {
        let num_entries = (*table_ptr).NumEntries;
        let rows_slice = std::slice::from_raw_parts(
            (*table_ptr).Table.as_ptr() as *const MIB_IPFORWARD_ROW2,
            num_entries as usize,
        );

        for row in rows_slice {
            let family = row.DestinationPrefix.Prefix.si_family;
            let prefix_length = row.DestinationPrefix.PrefixLength;

            let (destination_cidr, is_ipv6, is_unspec_dest) = if family == AF_INET {
                let sin_addr = row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr;
                let ip = Ipv4Addr::from(u32::from_be(sin_addr));
                (
                    format!("{}/{}", ip, prefix_length),
                    false,
                    ip.is_unspecified(),
                )
            } else if family == AF_INET6 {
                let bytes = row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte;
                let ip = Ipv6Addr::from(bytes);
                (
                    format!("{}/{}", ip, prefix_length),
                    true,
                    ip.is_unspecified(),
                )
            } else {
                continue;
            };

            let gateway_ip = if row.NextHop.si_family == AF_INET {
                let sin_addr = row.NextHop.Ipv4.sin_addr.S_un.S_addr;
                let ip = Ipv4Addr::from(u32::from_be(sin_addr));
                if ip.is_unspecified() {
                    None
                } else {
                    Some(ip.to_string())
                }
            } else if row.NextHop.si_family == AF_INET6 {
                let bytes = row.NextHop.Ipv6.sin6_addr.u.Byte;
                let ip = Ipv6Addr::from(bytes);
                if ip.is_unspecified() {
                    None
                } else {
                    Some(ip.to_string())
                }
            } else {
                None
            };

            let is_default_gateway = prefix_length == 0 && is_unspec_dest && gateway_ip.is_some();

            let route_type = if row.Loopback != 0
                || destination_cidr.starts_with("127.")
                || destination_cidr.starts_with("::1/")
            {
                RouteType::Local
            } else if gateway_ip.is_some() {
                RouteType::Remote
            } else {
                RouteType::Direct
            };

            // Query interface friendly alias
            let mut alias_buf = [0u16; 256];
            let alias_ret = ConvertInterfaceLuidToAlias(
                &row.InterfaceLuid,
                alias_buf.as_mut_ptr(),
                alias_buf.len() * std::mem::size_of::<u16>(),
            );
            let interface_name = if alias_ret == ERROR_SUCCESS {
                let len = alias_buf
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(alias_buf.len());
                String::from_utf16(&alias_buf[..len])
                    .ok()
                    .filter(|s| !s.is_empty())
            } else {
                None
            };

            routes.push(RouteRecord {
                destination_cidr,
                gateway_ip,
                interface_index: row.InterfaceIndex,
                interface_name,
                metric: row.Metric,
                is_ipv6,
                is_default_gateway,
                route_type,
            });
        }

        // Free the table allocated by GetIpForwardTable2
        FreeMibTable(table_ptr as *const _ as *const std::ffi::c_void);
    }

    // Deterministic route ordering: (is_ipv6, destination_cidr, metric, interface_index, gateway_ip)
    routes.sort_by(|a, b| {
        (
            a.is_ipv6,
            &a.destination_cidr,
            a.metric,
            a.interface_index,
            &a.gateway_ip,
        )
            .cmp(&(
                b.is_ipv6,
                &b.destination_cidr,
                b.metric,
                b.interface_index,
                &b.gateway_ip,
            ))
    });

    // Derive default gateways ordered strictly by lowest metric first
    let mut default_routes: Vec<&RouteRecord> = routes
        .iter()
        .filter(|r| r.is_default_gateway && r.gateway_ip.is_some())
        .collect();
    default_routes.sort_by_key(|r| r.metric);

    let mut default_gateways = Vec::new();
    for r in default_routes {
        if let Some(ref gw) = r.gateway_ip {
            if !default_gateways.contains(gw) {
                default_gateways.push(gw.clone());
            }
        }
    }

    Ok(ObservationPayload::Routes(RouteObservationPayload {
        routes,
        default_gateways,
    }))
}
