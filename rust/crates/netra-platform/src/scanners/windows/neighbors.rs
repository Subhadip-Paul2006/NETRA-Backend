//! Windows native Win32 IP Helper neighbor table collector (ARP for IPv4 and NDP for IPv6).

#[cfg(windows)]
use netra_core::error::{NetraError, Result};
#[cfg(windows)]
use netra_core::network::ip::IpClassification;
#[cfg(windows)]
use netra_core::network::mac::hash_mac_bytes;
#[cfg(windows)]
use netra_core::observation::{
    NeighborObservationPayload, NeighborRecord, NeighborState, ObservationPayload,
};
#[cfg(windows)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(windows)]
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToAlias, FreeMibTable, GetIpNetTable2, MIB_IPNET_ROW2, MIB_IPNET_TABLE2,
};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

/// Win32 NL_NEIGHBOR_STATE constants.
#[cfg(windows)]
const NLNS_UNREACHABLE: i32 = 0;
#[cfg(windows)]
const NLNS_INCOMPLETE: i32 = 1;
#[cfg(windows)]
const NLNS_PROBE: i32 = 2;
#[cfg(windows)]
const NLNS_DELAY: i32 = 3;
#[cfg(windows)]
const NLNS_STALE: i32 = 4;
#[cfg(windows)]
const NLNS_REACHABLE: i32 = 5;
#[cfg(windows)]
const NLNS_PERMANENT: i32 = 6;

/// Collects the current host Layer-2 / Layer-3 neighbor cache from the Windows kernel via `GetIpNetTable2`.
#[cfg(windows)]
pub fn collect_windows_neighbors() -> Result<ObservationPayload> {
    let mut table_ptr: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();

    // SAFETY: GetIpNetTable2 allocates and returns a pointer to MIB_IPNET_TABLE2.
    // Memory is freed unconditionally at the end of this scope via FreeMibTable.
    let ret = unsafe { GetIpNetTable2(AF_UNSPEC, &mut table_ptr) };

    if ret != ERROR_SUCCESS || table_ptr.is_null() {
        return Err(NetraError::platform(format!(
            "GetIpNetTable2 failed with Win32 error code {}",
            ret
        )));
    }

    let mut neighbors = Vec::new();

    unsafe {
        let num_entries = (*table_ptr).NumEntries;
        let rows_slice = std::slice::from_raw_parts(
            (*table_ptr).Table.as_ptr() as *const MIB_IPNET_ROW2,
            num_entries as usize,
        );

        for row in rows_slice {
            let family = row.Address.si_family;

            let (ip_addr, is_ipv6) = if family == AF_INET {
                let sin_addr = row.Address.Ipv4.sin_addr.S_un.S_addr;
                let ip = Ipv4Addr::from(u32::from_be(sin_addr));
                if ip.is_unspecified() || ip.is_loopback() {
                    continue;
                }
                (IpAddr::V4(ip), false)
            } else if family == AF_INET6 {
                let bytes = row.Address.Ipv6.sin6_addr.u.Byte;
                let ip = Ipv6Addr::from(bytes);
                if ip.is_unspecified() || ip.is_loopback() {
                    continue;
                }
                (IpAddr::V6(ip), true)
            } else {
                continue;
            };

            let ip_classification = IpClassification::classify(&ip_addr);

            // Convert InterfaceLuid to friendly interface alias
            let mut alias_buf = [0u16; 256];
            let name_res =
                ConvertInterfaceLuidToAlias(&row.InterfaceLuid, alias_buf.as_mut_ptr(), 256);
            let interface_name = if name_res == ERROR_SUCCESS {
                let len = alias_buf
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(alias_buf.len());
                if len > 0 {
                    Some(String::from_utf16_lossy(&alias_buf[..len]))
                } else {
                    None
                }
            } else {
                None
            };

            // Strict MAC pseudonymization: hash raw bytes immediately
            let mac_len = row.PhysicalAddressLength as usize;
            let mac_address_hash = if mac_len > 0 && mac_len <= row.PhysicalAddress.len() {
                let raw_bytes = &row.PhysicalAddress[..mac_len];
                let hash = hash_mac_bytes(raw_bytes);
                if hash.is_empty() {
                    None
                } else {
                    Some(hash)
                }
            } else {
                None
            };

            // Map Win32 NL_NEIGHBOR_STATE to NETRA NeighborState
            let state = match row.State {
                NLNS_REACHABLE => NeighborState::Reachable,
                NLNS_STALE => NeighborState::Stale,
                NLNS_DELAY => NeighborState::Delay,
                NLNS_PROBE => NeighborState::Probe,
                NLNS_INCOMPLETE | NLNS_UNREACHABLE => NeighborState::Incomplete,
                NLNS_PERMANENT => NeighborState::Permanent,
                _ => NeighborState::Unknown,
            };

            let record = NeighborRecord {
                ip_address: ip_addr.to_string(),
                mac_address_hash,
                interface_index: row.InterfaceIndex,
                interface_name,
                state,
                is_ipv6,
                ip_classification,
                is_router: None,
            };

            // Deduplicate exact matches on (ip_address, interface_index, interface_name)
            if !neighbors.iter().any(|r: &NeighborRecord| {
                r.ip_address == record.ip_address
                    && r.interface_index == record.interface_index
                    && r.interface_name == record.interface_name
            }) {
                neighbors.push(record);
            }
        }

        // Unconditionally free the kernel table memory
        FreeMibTable(table_ptr as *const _);
    }

    // Deterministic sorting across address family, IP, interface index, and interface name
    neighbors.sort_by(|a, b| {
        a.is_ipv6
            .cmp(&b.is_ipv6)
            .then_with(|| a.ip_address.cmp(&b.ip_address))
            .then_with(|| a.interface_index.cmp(&b.interface_index))
            .then_with(|| a.interface_name.cmp(&b.interface_name))
    });

    Ok(ObservationPayload::Neighbors(NeighborObservationPayload {
        neighbors,
    }))
}

/// Fallback for non-Windows platforms.
#[cfg(not(windows))]
pub fn collect_windows_neighbors(
) -> netra_core::error::Result<netra_core::observation::ObservationPayload> {
    Err(netra_core::error::NetraError::platform(
        "Windows neighbor collector is only supported on Windows targets",
    ))
}
