//! Linux /proc/net/dev and /sys/class/net network interface collector.

use netra_core::error::Result;
use netra_core::network::{hash_mac_str, IpClassification};
use netra_core::observation::{
    InterfaceObservationPayload, InterfaceRecord, InterfaceStatus, InterfaceType, IpNetworkRecord,
    ObservationPayload,
};
use std::fs;
use std::path::Path;

/// Translates Linux operstate string to [`InterfaceStatus`].
pub fn parse_linux_operstate(state: &str) -> InterfaceStatus {
    match state.trim().to_lowercase().as_str() {
        "up" => InterfaceStatus::Up,
        "down" => InterfaceStatus::Down,
        "testing" => InterfaceStatus::Testing,
        "dormant" => InterfaceStatus::Dormant,
        "notpresent" => InterfaceStatus::NotPresent,
        "lowerlayerdown" => InterfaceStatus::LowerLayerDown,
        _ => InterfaceStatus::Unknown,
    }
}

/// Parses a Linux `/proc/net/dev` content string into a list of [`InterfaceRecord`] items.
pub fn parse_proc_net_dev(content: &str) -> Vec<InterfaceRecord> {
    let mut interfaces = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.contains(':') || trimmed.starts_with("Inter-") || trimmed.starts_with("face") {
            continue;
        }

        let mut parts = trimmed.split(':');
        let iface_name = match parts.next() {
            Some(name) => name.trim().to_string(),
            None => continue,
        };

        let is_loopback = iface_name == "lo";
        let interface_type = if is_loopback {
            InterfaceType::Loopback
        } else if iface_name.starts_with("wl") {
            InterfaceType::Wireless
        } else if iface_name.starts_with("tun") || iface_name.starts_with("tap") {
            InterfaceType::Tunnel
        } else if iface_name.starts_with("eth") || iface_name.starts_with("en") {
            InterfaceType::Ethernet
        } else {
            InterfaceType::Other
        };

        let index = (interfaces.len() as u32) + 1;
        interfaces.push(InterfaceRecord {
            interface_name: iface_name.clone(),
            friendly_name: Some(iface_name),
            interface_index: index,
            mac_address_hash: None,
            interface_type,
            oper_status: InterfaceStatus::Unknown,
            ip_addresses: Vec::new(),
            mtu: 1500,
            is_loopback,
            is_point_to_point: false,
            is_dhcp_enabled: None,
            is_virtual: interface_type == InterfaceType::Tunnel
                || interface_type == InterfaceType::Virtual,
        });
    }

    interfaces
}

/// Collects Linux network interfaces from `/sys/class/net` and `/proc/net/dev`.
pub fn collect_linux_interfaces() -> Result<ObservationPayload> {
    let sys_net = Path::new("/sys/class/net");
    let mut interfaces = Vec::new();

    if sys_net.exists() && sys_net.is_dir() {
        if let Ok(entries) = fs::read_dir(sys_net) {
            for (index, entry) in (1u32..).zip(entries.flatten()) {
                let name = entry.file_name().to_string_lossy().to_string();
                let iface_path = entry.path();

                let operstate = fs::read_to_string(iface_path.join("operstate"))
                    .map(|s| parse_linux_operstate(&s))
                    .unwrap_or(InterfaceStatus::Unknown);

                let is_loopback = name == "lo";
                let mac_address_hash = if !is_loopback {
                    fs::read_to_string(iface_path.join("address"))
                        .ok()
                        .and_then(|addr| hash_mac_str(addr.trim()))
                } else {
                    None
                };

                let mtu = fs::read_to_string(iface_path.join("mtu"))
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(1500);

                let interface_type = if is_loopback {
                    InterfaceType::Loopback
                } else if name.starts_with("wl") {
                    InterfaceType::Wireless
                } else if name.starts_with("tun") || name.starts_with("tap") {
                    InterfaceType::Tunnel
                } else if name.starts_with("eth") || name.starts_with("en") {
                    InterfaceType::Ethernet
                } else {
                    InterfaceType::Other
                };

                let is_virtual = !iface_path.join("device").exists() && !is_loopback;

                let mut ip_addresses = Vec::new();
                if is_loopback {
                    ip_addresses.push(IpNetworkRecord {
                        ip_address: "127.0.0.1".to_string(),
                        prefix_length: 8,
                        is_ipv6: false,
                        classification: IpClassification::Loopback,
                        broadcast_address: None,
                    });
                    ip_addresses.push(IpNetworkRecord {
                        ip_address: "::1".to_string(),
                        prefix_length: 128,
                        is_ipv6: true,
                        classification: IpClassification::Loopback,
                        broadcast_address: None,
                    });
                }

                interfaces.push(InterfaceRecord {
                    interface_name: name.clone(),
                    friendly_name: Some(name),
                    interface_index: index,
                    mac_address_hash,
                    interface_type,
                    oper_status: operstate,
                    ip_addresses,
                    mtu,
                    is_loopback,
                    is_point_to_point: false,
                    is_dhcp_enabled: None,
                    is_virtual,
                });
            }
        }
    } else if let Ok(content) = fs::read_to_string("/proc/net/dev") {
        interfaces = parse_proc_net_dev(&content);
    }

    Ok(ObservationPayload::Interfaces(
        InterfaceObservationPayload { interfaces },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_net_dev_fixture() {
        let fixture = r#"Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 4892429   32087    0    0    0     0          0         0  4892429   32087    0    0    0     0       0          0
  eth0: 92837482  102934    0    0    0     0          0         0  1293849   49382    0    0    0     0       0          0
 wlan0: 12938492   29384    0    0    0     0          0         0   493829   10293    0    0    0     0       0          0
"#;

        let interfaces = parse_proc_net_dev(fixture);
        assert_eq!(interfaces.len(), 3);
        assert_eq!(interfaces[0].interface_name, "lo");
        assert_eq!(interfaces[0].interface_type, InterfaceType::Loopback);
        assert_eq!(interfaces[1].interface_name, "eth0");
        assert_eq!(interfaces[1].interface_type, InterfaceType::Ethernet);
        assert_eq!(interfaces[2].interface_name, "wlan0");
        assert_eq!(interfaces[2].interface_type, InterfaceType::Wireless);
    }

    #[test]
    fn test_parse_linux_operstate() {
        assert_eq!(parse_linux_operstate("up"), InterfaceStatus::Up);
        assert_eq!(parse_linux_operstate("down\n"), InterfaceStatus::Down);
        assert_eq!(parse_linux_operstate("dormant"), InterfaceStatus::Dormant);
        assert_eq!(parse_linux_operstate("unknown"), InterfaceStatus::Unknown);
    }
}
