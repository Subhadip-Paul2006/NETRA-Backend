//! Windows native Win32 IP Helper DNS configuration collector.

#[cfg(windows)]
use netra_core::error::{NetraError, Result};
#[cfg(windows)]
use netra_core::network::IpClassification;
#[cfg(windows)]
use netra_core::observation::{DnsObservationPayload, DnsServerRecord, ObservationPayload};
#[cfg(windows)]
use std::ffi::CStr;
#[cfg(windows)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS};
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
};

#[cfg(windows)]
unsafe fn pwstr_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    if len == 0 {
        return None;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    let s = String::from_utf16_lossy(slice).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Collects configured DNS servers and adapter DNS suffixes from the Windows kernel via `GetAdaptersAddresses`.
#[cfg(windows)]
pub fn collect_windows_dns() -> Result<ObservationPayload> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;

    let mut size: u32 = 15000;
    let mut buffer: Vec<u8> = vec![0u8; size as usize];

    let mut ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            flags,
            std::ptr::null_mut(),
            buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut size,
        )
    };

    if ret == ERROR_BUFFER_OVERFLOW {
        buffer.resize(size as usize, 0);
        ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null_mut(),
                buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
    }

    if ret == ERROR_NO_DATA {
        return Ok(ObservationPayload::Dns(DnsObservationPayload {
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            is_dynamic_dns_enabled: None,
        }));
    }

    if ret != ERROR_SUCCESS {
        return Err(NetraError::platform(format!(
            "GetAdaptersAddresses failed with Win32 error code: {}",
            ret
        )));
    }

    let mut dns_servers: Vec<DnsServerRecord> = Vec::new();
    let mut search_domains: Vec<String> = Vec::new();

    let mut curr_adapter = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !curr_adapter.is_null() {
        let adapter = unsafe { &*curr_adapter };

        // 1. Resolve interface name / alias
        let iface_name = unsafe {
            pwstr_to_string(adapter.FriendlyName as *const u16).or_else(|| {
                if !adapter.AdapterName.is_null() {
                    Some(
                        CStr::from_ptr(adapter.AdapterName as *const i8)
                            .to_string_lossy()
                            .into_owned(),
                    )
                } else {
                    None
                }
            })
        };

        // 2. Capture connection-specific DNS suffix
        if let Some(suffix) = unsafe { pwstr_to_string(adapter.DnsSuffix as *const u16) } {
            if !suffix.is_empty() && !search_domains.contains(&suffix) {
                search_domains.push(suffix);
            }
        }

        // 3. Walk DNS Server linked list
        let mut curr_dns = adapter.FirstDnsServerAddress;
        while !curr_dns.is_null() {
            let dns_node = unsafe { &*curr_dns };
            let sockaddr_ptr = dns_node.Address.lpSockaddr;

            if !sockaddr_ptr.is_null() {
                let family = unsafe { (*sockaddr_ptr).sa_family };

                if family == AF_INET {
                    let sin = unsafe { &*(sockaddr_ptr as *const SOCKADDR_IN) };
                    let ip = unsafe { Ipv4Addr::from(sin.sin_addr.S_un.S_addr.to_ne_bytes()) };

                    if !ip.is_unspecified() {
                        let ip_addr = IpAddr::V4(ip);
                        let classification = IpClassification::classify(&ip_addr);
                        let record = DnsServerRecord {
                            server_address: ip.to_string(),
                            interface_name: iface_name.clone(),
                            is_ipv6: false,
                            classification,
                        };

                        if !dns_servers.iter().any(|r| {
                            r.server_address == record.server_address
                                && r.interface_name == record.interface_name
                        }) {
                            dns_servers.push(record);
                        }
                    }
                } else if family == AF_INET6 {
                    let sin6 = unsafe { &*(sockaddr_ptr as *const SOCKADDR_IN6) };
                    let ip = unsafe { Ipv6Addr::from(sin6.sin6_addr.u.Byte) };

                    if !ip.is_unspecified() {
                        let ip_addr = IpAddr::V6(ip);
                        let classification = IpClassification::classify(&ip_addr);
                        let record = DnsServerRecord {
                            server_address: ip.to_string(),
                            interface_name: iface_name.clone(),
                            is_ipv6: true,
                            classification,
                        };

                        if !dns_servers.iter().any(|r| {
                            r.server_address == record.server_address
                                && r.interface_name == record.interface_name
                        }) {
                            dns_servers.push(record);
                        }
                    }
                }
            }

            curr_dns = dns_node.Next;
        }

        curr_adapter = adapter.Next;
    }

    Ok(ObservationPayload::Dns(DnsObservationPayload {
        dns_servers,
        search_domains,
        is_dynamic_dns_enabled: None,
    }))
}

#[cfg(not(windows))]
pub fn collect_windows_dns() -> Result<ObservationPayload> {
    Err(NetraError::platform(
        "Windows DNS scanner is not supported on non-Windows platforms",
    ))
}
