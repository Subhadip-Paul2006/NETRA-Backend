//! Linux passive neighbor table parser & collector (Netlink IPv4/IPv6 NDP and /proc/net/arp fallback).

use netra_core::error::{NetraError, Result};
use netra_core::network::ip::IpClassification;
use netra_core::network::mac::{hash_mac_bytes, hash_mac_str};
use netra_core::observation::{
    NeighborObservationPayload, NeighborRecord, NeighborState, ObservationPayload,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

// Standard Linux Netlink and Neighbor constants
const AF_INET_U8: u8 = 2;
const AF_INET6_U8: u8 = 10;
const RTM_NEWNEIGH_TYPE: u16 = 28;
const NLMSG_DONE_TYPE: u16 = 3;

// Linux NUD (Neighbor Unreachability Detection) state flags
const NUD_INCOMPLETE: u16 = 0x01;
const NUD_REACHABLE: u16 = 0x02;
const NUD_STALE: u16 = 0x04;
const NUD_DELAY: u16 = 0x08;
const NUD_PROBE: u16 = 0x10;
const NUD_FAILED: u16 = 0x20;
const NUD_NOARP: u16 = 0x40;
const NUD_PERMANENT: u16 = 0x80;

// Linux Neighbor Attributes
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NTF_ROUTER: u8 = 0x80;

/// Parses standard Linux `/proc/net/arp` file contents (IPv4 ARP only).
pub fn parse_proc_net_arp(content: &str) -> Vec<NeighborRecord> {
    let mut neighbors = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("IP address") {
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 6 {
            continue;
        }

        let ip_str = tokens[0];
        let flags_str = tokens[2];
        let hw_addr_str = tokens[3];
        let device_str = tokens[5];

        let ip_addr = match IpAddr::from_str(ip_str) {
            Ok(ip) => {
                if ip.is_unspecified() || ip.is_loopback() {
                    continue;
                }
                ip
            }
            Err(_) => continue,
        };

        let flags = if let Some(hex_part) = flags_str.strip_prefix("0x") {
            u32::from_str_radix(hex_part, 16).unwrap_or(0)
        } else {
            flags_str.parse::<u32>().unwrap_or(0)
        };

        let state = if flags == 0 {
            NeighborState::Incomplete
        } else if (flags & 0x4) != 0 {
            NeighborState::Permanent
        } else if (flags & 0x2) != 0 {
            NeighborState::Reachable
        } else {
            NeighborState::Stale
        };

        let mac_address_hash = hash_mac_str(hw_addr_str);
        let ip_classification = IpClassification::classify(&ip_addr);

        let record = NeighborRecord {
            ip_address: ip_addr.to_string(),
            mac_address_hash,
            interface_index: 0,
            interface_name: Some(device_str.to_string()),
            state,
            is_ipv6: false,
            ip_classification,
            is_router: None,
        };

        if !neighbors.iter().any(|r: &NeighborRecord| {
            r.ip_address == record.ip_address && r.interface_name == record.interface_name
        }) {
            neighbors.push(record);
        }
    }

    neighbors.sort_by(|a, b| {
        a.is_ipv6
            .cmp(&b.is_ipv6)
            .then_with(|| a.ip_address.cmp(&b.ip_address))
            .then_with(|| a.interface_index.cmp(&b.interface_index))
            .then_with(|| a.interface_name.cmp(&b.interface_name))
    });

    neighbors
}

/// Parses a binary Linux Netlink `RTM_GETNEIGH` response buffer containing IPv4 ARP and IPv6 NDP entries.
pub fn parse_netlink_neighbors(buf: &[u8]) -> Vec<NeighborRecord> {
    let mut neighbors = Vec::new();
    let mut offset = 0;

    while offset + 16 <= buf.len() {
        // Parse nlmsghdr (16 bytes)
        let nlmsg_len = u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
        let nlmsg_type = u16::from_ne_bytes(buf[offset + 4..offset + 6].try_into().unwrap());

        if nlmsg_len < 16 || offset + nlmsg_len > buf.len() {
            break;
        }

        if nlmsg_type == NLMSG_DONE_TYPE {
            break;
        }

        if nlmsg_type == RTM_NEWNEIGH_TYPE && nlmsg_len >= 16 + 12 {
            let ndmsg_offset = offset + 16;
            let ndm_family = buf[ndmsg_offset];
            let ndm_ifindex =
                i32::from_ne_bytes(buf[ndmsg_offset + 4..ndmsg_offset + 8].try_into().unwrap())
                    as u32;
            let ndm_state =
                u16::from_ne_bytes(buf[ndmsg_offset + 8..ndmsg_offset + 10].try_into().unwrap());
            let ndm_flags = buf[ndmsg_offset + 10];

            let is_router = if (ndm_flags & NTF_ROUTER) != 0 {
                Some(true)
            } else {
                None
            };

            let state = match ndm_state {
                NUD_REACHABLE => NeighborState::Reachable,
                NUD_STALE => NeighborState::Stale,
                NUD_DELAY => NeighborState::Delay,
                NUD_PROBE => NeighborState::Probe,
                NUD_INCOMPLETE | NUD_FAILED => NeighborState::Incomplete,
                NUD_PERMANENT | NUD_NOARP => NeighborState::Permanent,
                _ => NeighborState::Unknown,
            };

            // Parse rtattr attributes (starting at offset + 16 + 12 = offset + 28)
            let mut attr_offset = ndmsg_offset + 12;
            let msg_end = offset + nlmsg_len;

            let mut parsed_ip: Option<IpAddr> = None;
            let mut parsed_mac_hash: Option<String> = None;

            while attr_offset + 4 <= msg_end {
                let rta_len =
                    u16::from_ne_bytes(buf[attr_offset..attr_offset + 2].try_into().unwrap())
                        as usize;
                let rta_type =
                    u16::from_ne_bytes(buf[attr_offset + 2..attr_offset + 4].try_into().unwrap());

                if rta_len < 4 || attr_offset + rta_len > msg_end {
                    break;
                }

                let data_offset = attr_offset + 4;
                let data_len = rta_len - 4;
                let data = &buf[data_offset..data_offset + data_len];

                match rta_type {
                    NDA_DST => {
                        if ndm_family == AF_INET_U8 && data.len() >= 4 {
                            let octets: [u8; 4] = data[..4].try_into().unwrap();
                            let ip = Ipv4Addr::from(octets);
                            if !ip.is_unspecified() && !ip.is_loopback() {
                                parsed_ip = Some(IpAddr::V4(ip));
                            }
                        } else if ndm_family == AF_INET6_U8 && data.len() >= 16 {
                            let octets: [u8; 16] = data[..16].try_into().unwrap();
                            let ip = Ipv6Addr::from(octets);
                            if !ip.is_unspecified() && !ip.is_loopback() {
                                parsed_ip = Some(IpAddr::V6(ip));
                            }
                        }
                    }
                    NDA_LLADDR if !data.is_empty() => {
                        let hash = hash_mac_bytes(data);
                        if !hash.is_empty() {
                            parsed_mac_hash = Some(hash);
                        }
                    }
                    _ => {}
                }

                // Align to 4 bytes
                let aligned_len = (rta_len + 3) & !3;
                attr_offset += aligned_len;
            }

            if let Some(ip) = parsed_ip {
                let is_ipv6 = ip.is_ipv6();
                let ip_classification = IpClassification::classify(&ip);
                let record = NeighborRecord {
                    ip_address: ip.to_string(),
                    mac_address_hash: parsed_mac_hash,
                    interface_index: ndm_ifindex,
                    interface_name: None,
                    state,
                    is_ipv6,
                    ip_classification,
                    is_router,
                };

                if !neighbors.iter().any(|r: &NeighborRecord| {
                    r.ip_address == record.ip_address && r.interface_index == record.interface_index
                }) {
                    neighbors.push(record);
                }
            }
        }

        // Align nlmsghdr to 4 bytes
        let aligned_len = (nlmsg_len + 3) & !3;
        offset += aligned_len;
    }

    neighbors.sort_by(|a, b| {
        a.is_ipv6
            .cmp(&b.is_ipv6)
            .then_with(|| a.ip_address.cmp(&b.ip_address))
            .then_with(|| a.interface_index.cmp(&b.interface_index))
            .then_with(|| a.interface_name.cmp(&b.interface_name))
    });

    neighbors
}

/// Collects neighbor table observations from the Linux kernel using Netlink with `/proc/net/arp` fallback.
#[cfg(target_os = "linux")]
pub fn collect_linux_neighbors() -> Result<ObservationPayload> {
    // 1. Try Netlink RTM_GETNEIGH socket query (IPv4 ARP + IPv6 NDP)
    let netlink_res = query_linux_netlink_neighbors();
    if let Ok(neighbors) = netlink_res {
        if !neighbors.is_empty() {
            return Ok(ObservationPayload::Neighbors(NeighborObservationPayload {
                neighbors,
            }));
        }
    }

    // 2. Fallback to /proc/net/arp (IPv4 ARP)
    if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
        let neighbors = parse_proc_net_arp(&content);
        return Ok(ObservationPayload::Neighbors(NeighborObservationPayload {
            neighbors,
        }));
    }

    Ok(ObservationPayload::Neighbors(
        NeighborObservationPayload::default(),
    ))
}

#[cfg(target_os = "linux")]
fn query_linux_netlink_neighbors() -> Result<Vec<NeighborRecord>> {
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if fd < 0 {
            return Err(NetraError::platform("Failed to open AF_NETLINK socket"));
        }

        #[repr(C)]
        struct NetlinkReq {
            nlh: libc::nlmsghdr,
            ndm: libc::ndmsg,
        }

        let mut req: NetlinkReq = std::mem::zeroed();
        req.nlh.nlmsg_len = std::mem::size_of::<NetlinkReq>() as u32;
        req.nlh.nlmsg_type = libc::RTM_GETNEIGH as u16;
        req.nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
        req.nlh.nlmsg_seq = 1;
        req.ndm.ndm_family = libc::AF_UNSPEC as u8;

        let sent = libc::send(
            fd,
            &req as *const _ as *const libc::c_void,
            std::mem::size_of::<NetlinkReq>(),
            0,
        );

        if sent < 0 {
            libc::close(fd);
            return Err(NetraError::platform(
                "Failed to send RTM_GETNEIGH netlink request",
            ));
        }

        let mut buf = vec![0u8; 16384];
        let mut total_bytes = Vec::new();

        loop {
            let received = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if received <= 0 {
                break;
            }
            let n = received as usize;
            total_bytes.extend_from_slice(&buf[..n]);

            // Check for NLMSG_DONE
            if n >= 16 {
                let nlmsg_type = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
                if nlmsg_type == libc::NLMSG_DONE as u16 {
                    break;
                }
            }
        }

        libc::close(fd);
        Ok(parse_netlink_neighbors(&total_bytes))
    }
}

/// Fallback for non-Linux targets.
#[cfg(not(target_os = "linux"))]
pub fn collect_linux_neighbors() -> Result<ObservationPayload> {
    Err(NetraError::platform(
        "Linux neighbor collector is only supported on Linux targets",
    ))
}
