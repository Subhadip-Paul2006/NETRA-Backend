//! Windows native Win32 IP Helper network interface collector.

#[cfg(windows)]
use netra_core::error::{NetraError, Result};
#[cfg(windows)]
use netra_core::network::{hash_mac_bytes, IpClassification};
#[cfg(windows)]
use netra_core::observation::{
    InterfaceObservationPayload, InterfaceRecord, InterfaceStatus, InterfaceType, IpNetworkRecord,
    ObservationPayload,
};
#[cfg(windows)]
use std::ffi::CStr;
#[cfg(windows)]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS};
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_PPP,
    IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DHCP_ENABLED,
};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
};

#[cfg(windows)]
const IF_OPER_STATUS_UP: i32 = 1;
#[cfg(windows)]
const IF_OPER_STATUS_DOWN: i32 = 2;
#[cfg(windows)]
const IF_OPER_STATUS_TESTING: i32 = 3;
#[cfg(windows)]
const IF_OPER_STATUS_DORMANT: i32 = 4;
#[cfg(windows)]
const IF_OPER_STATUS_NOT_PRESENT: i32 = 5;
#[cfg(windows)]
const IF_OPER_STATUS_LOWER_LAYER_DOWN: i32 = 6;

/// Collects all network interfaces and associated IP addresses from the Windows kernel via `GetAdaptersAddresses`.
#[cfg(windows)]
pub fn collect_windows_interfaces() -> Result<ObservationPayload> {
    let flags = GAA_FLAG_INCLUDE_PREFIX
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;

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
        return Ok(ObservationPayload::Interfaces(
            InterfaceObservationPayload::default(),
        ));
    }

    if ret != ERROR_SUCCESS {
        return Err(NetraError::platform(format!(
            "GetAdaptersAddresses failed with Win32 error code {}",
            ret
        )));
    }

    let mut interfaces = Vec::new();
    let mut curr_ptr = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

    while !curr_ptr.is_null() {
        let adapter = unsafe { &*curr_ptr };
        let if_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };

        // 1. Adapter Identifier & Names
        let adapter_guid = if !adapter.AdapterName.is_null() {
            unsafe { CStr::from_ptr(adapter.AdapterName as *const i8) }
                .to_string_lossy()
                .to_string()
        } else {
            format!("iface_{}", if_index)
        };

        let friendly_name = if !adapter.FriendlyName.is_null() {
            let mut len = 0;
            while unsafe { *adapter.FriendlyName.add(len) } != 0 {
                len += 1;
            }
            let wide_slice = unsafe { std::slice::from_raw_parts(adapter.FriendlyName, len) };
            Some(String::from_utf16_lossy(wide_slice))
        } else {
            None
        };

        let description = if !adapter.Description.is_null() {
            let mut len = 0;
            while unsafe { *adapter.Description.add(len) } != 0 {
                len += 1;
            }
            let wide_slice = unsafe { std::slice::from_raw_parts(adapter.Description, len) };
            String::from_utf16_lossy(wide_slice)
        } else {
            String::new()
        };

        // Prefer human-readable friendly name as interface name if available, fallback to GUID
        let interface_name = friendly_name
            .clone()
            .unwrap_or_else(|| adapter_guid.clone());

        // 2. Operational Status
        let oper_status = match adapter.OperStatus {
            IF_OPER_STATUS_UP => InterfaceStatus::Up,
            IF_OPER_STATUS_DOWN => InterfaceStatus::Down,
            IF_OPER_STATUS_TESTING => InterfaceStatus::Testing,
            IF_OPER_STATUS_DORMANT => InterfaceStatus::Dormant,
            IF_OPER_STATUS_NOT_PRESENT => InterfaceStatus::NotPresent,
            IF_OPER_STATUS_LOWER_LAYER_DOWN => InterfaceStatus::LowerLayerDown,
            _ => InterfaceStatus::Unknown,
        };

        // 3. Interface Type
        let interface_type = match adapter.IfType {
            IF_TYPE_ETHERNET_CSMACD => InterfaceType::Ethernet,
            IF_TYPE_IEEE80211 => InterfaceType::Wireless,
            IF_TYPE_SOFTWARE_LOOPBACK => InterfaceType::Loopback,
            IF_TYPE_TUNNEL => InterfaceType::Tunnel,
            IF_TYPE_PPP => InterfaceType::Ppp,
            _ => {
                if description.to_lowercase().contains("virtual")
                    || description.to_lowercase().contains("hyper-v")
                    || description.to_lowercase().contains("vmware")
                    || description.to_lowercase().contains("tap")
                    || description.to_lowercase().contains("vpn")
                {
                    InterfaceType::Virtual
                } else {
                    InterfaceType::Other
                }
            }
        };

        let is_loopback = adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK;
        let is_point_to_point = adapter.IfType == IF_TYPE_PPP || adapter.IfType == IF_TYPE_TUNNEL;
        let is_virtual = interface_type == InterfaceType::Virtual
            || interface_type == InterfaceType::Tunnel
            || description.to_lowercase().contains("virtual");

        // 4. Pseudonymized MAC Address (RAW MAC IS NEVER STORED)
        let mac_address_hash = if adapter.PhysicalAddressLength > 0 && !is_loopback {
            let mac_len = (adapter.PhysicalAddressLength as usize).min(8);
            let mac_slice = &adapter.PhysicalAddress[..mac_len];
            let hash = hash_mac_bytes(mac_slice);
            if hash.is_empty() {
                None
            } else {
                Some(hash)
            }
        } else {
            None
        };

        // 5. Unicast IP Addresses
        let mut ip_addresses = Vec::new();
        let mut unicast_ptr = adapter.FirstUnicastAddress;

        while !unicast_ptr.is_null() {
            let unicast = unsafe { &*unicast_ptr };
            let sockaddr_ptr = unicast.Address.lpSockaddr as *const SOCKADDR;

            if !sockaddr_ptr.is_null() {
                let family = unsafe { (*sockaddr_ptr).sa_family };

                if family == AF_INET {
                    let sin = unsafe { &*(sockaddr_ptr as *const SOCKADDR_IN) };
                    let ipv4 = Ipv4Addr::from(u32::from_be(unsafe { sin.sin_addr.S_un.S_addr }));
                    let prefix_length = unicast.OnLinkPrefixLength;
                    let classification = IpClassification::classify_v4(&ipv4);

                    ip_addresses.push(IpNetworkRecord {
                        ip_address: ipv4.to_string(),
                        prefix_length,
                        is_ipv6: false,
                        classification,
                        broadcast_address: None,
                    });
                } else if family == AF_INET6 {
                    let sin6 = unsafe { &*(sockaddr_ptr as *const SOCKADDR_IN6) };
                    let ipv6 = Ipv6Addr::from(unsafe { sin6.sin6_addr.u.Byte });
                    let prefix_length = unicast.OnLinkPrefixLength;
                    let classification = IpClassification::classify_v6(&ipv6);

                    ip_addresses.push(IpNetworkRecord {
                        ip_address: ipv6.to_string(),
                        prefix_length,
                        is_ipv6: true,
                        classification,
                        broadcast_address: None,
                    });
                }
            }

            unicast_ptr = unicast.Next;
        }

        let is_dhcp_enabled =
            Some((unsafe { adapter.Anonymous2.Flags } & IP_ADAPTER_DHCP_ENABLED) != 0);

        interfaces.push(InterfaceRecord {
            interface_name,
            friendly_name,
            interface_index: if_index,
            mac_address_hash,
            interface_type,
            oper_status,
            ip_addresses,
            mtu: adapter.Mtu,
            is_loopback,
            is_point_to_point,
            is_dhcp_enabled,
            is_virtual,
        });

        curr_ptr = adapter.Next;
    }

    Ok(ObservationPayload::Interfaces(
        InterfaceObservationPayload { interfaces },
    ))
}
