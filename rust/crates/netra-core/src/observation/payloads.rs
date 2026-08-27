use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported transport layer socket protocols.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum SocketProtocol {
    Tcp,
    Udp,
}

impl fmt::Display for SocketProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

/// A structured record representing a single host network socket endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SocketRecord {
    pub protocol: SocketProtocol,
    pub local_address: String,
    pub local_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,
    pub state: String,
    pub owning_pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
}

/// Domain payload for socket and listening port observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SocketObservationPayload {
    pub sockets: Vec<SocketRecord>,
}

/// A structured record representing an active operating system process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessRecord {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256_binary_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub memory_rss_bytes: u64,
    pub has_command_line_args: bool,
}

/// Domain payload for process observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProcessObservationPayload {
    pub processes: Vec<ProcessRecord>,
}

/// A structured record representing a host firewall profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallProfileRecord {
    pub profile_name: String,
    pub is_enabled: bool,
    pub default_inbound_action: String,
    pub default_outbound_action: String,
    pub active_rules_count: usize,
}

/// Domain payload for host firewall observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FirewallObservationPayload {
    pub profiles: Vec<FirewallProfileRecord>,
}

/// A structured record representing a local operating system user account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRecord {
    pub username: String,
    pub uid_or_sid: String,
    pub is_enabled: bool,
    pub is_admin: bool,
    pub account_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_logon_timestamp: Option<DateTime<Utc>>,
}

/// Domain payload for user account observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UserObservationPayload {
    pub users: Vec<UserRecord>,
}

/// Operating system service runtime state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ServiceState {
    Running,
    Stopped,
    Paused,
    Unknown,
}

/// Operating system service startup configuration type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ServiceStartType {
    Auto,
    Manual,
    Disabled,
    Unknown,
}

/// A structured record representing an installed system service or background daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceRecord {
    pub service_name: String,
    pub display_name: String,
    pub state: ServiceState,
    pub start_type: ServiceStartType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_context: Option<String>,
}

/// Domain payload for system service observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ServiceObservationPayload {
    pub services: Vec<ServiceRecord>,
}

/// A structured record representing an operating system security hardening configuration check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OsConfigRecord {
    pub check_name: String,
    pub status: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Domain payload for operating system configuration observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OsConfigObservationPayload {
    pub configurations: Vec<OsConfigRecord>,
}

/// Network interface hardware or logical type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InterfaceType {
    Ethernet,
    Wireless,
    Loopback,
    Tunnel,
    Virtual,
    Ppp,
    Bridge,
    Other,
}

/// Operational state of a network interface.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InterfaceStatus {
    Up,
    Down,
    Testing,
    Dormant,
    NotPresent,
    LowerLayerDown,
    Unknown,
}

/// Structured record representing an IP address bound to a network interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpNetworkRecord {
    pub ip_address: String,
    pub prefix_length: u8,
    pub is_ipv6: bool,
    pub classification: crate::network::IpClassification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcast_address: Option<String>,
}

/// Structured record representing a single host network interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceRecord {
    pub interface_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    pub interface_index: u32,
    /// Pseudonymized SHA-256 hash of hardware MAC address (RAW MAC IS NEVER STORED).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address_hash: Option<String>,
    pub interface_type: InterfaceType,
    pub oper_status: InterfaceStatus,
    pub ip_addresses: Vec<IpNetworkRecord>,
    pub mtu: u32,
    pub is_loopback: bool,
    pub is_point_to_point: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_dhcp_enabled: Option<bool>,
    pub is_virtual: bool,
}

/// Domain payload for network interface observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct InterfaceObservationPayload {
    pub interfaces: Vec<InterfaceRecord>,
}

/// Route destination category.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RouteType {
    Direct,
    Remote,
    Local,
    Blackhole,
    Other,
}

/// Structured record representing a kernel routing table entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteRecord {
    pub destination_cidr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_ip: Option<String>,
    pub interface_index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,
    pub metric: u32,
    pub is_ipv6: bool,
    pub is_default_gateway: bool,
    pub route_type: RouteType,
}

/// Domain payload for kernel routing table observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RouteObservationPayload {
    pub routes: Vec<RouteRecord>,
    /// Pre-derived default gateways identified from routes with lowest metrics.
    pub default_gateways: Vec<String>,
}

/// Structured record representing a configured DNS nameserver.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsServerRecord {
    pub server_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,
    pub is_ipv6: bool,
    pub classification: crate::network::IpClassification,
}

/// Domain payload for host DNS configuration observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DnsObservationPayload {
    pub dns_servers: Vec<DnsServerRecord>,
    pub search_domains: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_dynamic_dns_enabled: Option<bool>,
}

/// Neighbor ARP / NDP cache entry state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NeighborState {
    Reachable,
    Stale,
    Delay,
    Probe,
    Incomplete,
    Permanent,
    Unknown,
}

/// Structured record representing a passive ARP / NDP neighbor cache entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NeighborRecord {
    pub ip_address: String,
    /// Pseudonymized SHA-256 hash of neighbor MAC address (RAW MAC IS NEVER STORED).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address_hash: Option<String>,
    pub interface_index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,
    pub state: NeighborState,
    pub is_ipv6: bool,
    pub ip_classification: crate::network::IpClassification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_router: Option<bool>,
}

/// Domain payload for passive ARP / NDP neighbor cache observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NeighborObservationPayload {
    pub neighbors: Vec<NeighborRecord>,
}

/// Top-level strongly typed enum wrapping all supported observation domain payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "domain", content = "data", rename_all = "snake_case")]
pub enum ObservationPayload {
    Processes(ProcessObservationPayload),
    Sockets(SocketObservationPayload),
    Firewall(FirewallObservationPayload),
    Users(UserObservationPayload),
    Services(ServiceObservationPayload),
    OsConfig(OsConfigObservationPayload),
    Interfaces(InterfaceObservationPayload),
    Routes(RouteObservationPayload),
    Dns(DnsObservationPayload),
    Neighbors(NeighborObservationPayload),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::IpClassification;

    #[test]
    fn test_payload_serialization_roundtrip() {
        let payload = ObservationPayload::Sockets(SocketObservationPayload {
            sockets: vec![SocketRecord {
                protocol: SocketProtocol::Tcp,
                local_address: "0.0.0.0".to_string(),
                local_port: 80,
                remote_address: None,
                remote_port: None,
                state: "LISTEN".to_string(),
                owning_pid: 1024,
                process_name: Some("nginx.exe".to_string()),
            }],
        });

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"domain\":\"sockets\""));
        assert!(json.contains("\"local_port\":80"));

        let deserialized: ObservationPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(payload, deserialized);
    }

    #[test]
    fn test_network_payloads_serialization_roundtrip() {
        // 1. Interfaces payload
        let iface_payload = ObservationPayload::Interfaces(InterfaceObservationPayload {
            interfaces: vec![InterfaceRecord {
                interface_name: "eth0".to_string(),
                friendly_name: Some("Ethernet Adapter".to_string()),
                interface_index: 2,
                mac_address_hash: Some(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                ),
                interface_type: InterfaceType::Ethernet,
                oper_status: InterfaceStatus::Up,
                ip_addresses: vec![IpNetworkRecord {
                    ip_address: "192.168.1.100".to_string(),
                    prefix_length: 24,
                    is_ipv6: false,
                    classification: IpClassification::Private,
                    broadcast_address: Some("192.168.1.255".to_string()),
                }],
                mtu: 1500,
                is_loopback: false,
                is_point_to_point: false,
                is_dhcp_enabled: Some(true),
                is_virtual: false,
            }],
        });
        let iface_json = serde_json::to_string(&iface_payload).unwrap();
        assert!(iface_json.contains("\"domain\":\"interfaces\""));
        let iface_deser: ObservationPayload = serde_json::from_str(&iface_json).unwrap();
        assert_eq!(iface_payload, iface_deser);

        // 2. Routes payload
        let route_payload = ObservationPayload::Routes(RouteObservationPayload {
            routes: vec![RouteRecord {
                destination_cidr: "0.0.0.0/0".to_string(),
                gateway_ip: Some("192.168.1.1".to_string()),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                metric: 25,
                is_ipv6: false,
                is_default_gateway: true,
                route_type: RouteType::Remote,
            }],
            default_gateways: vec!["192.168.1.1".to_string()],
        });
        let route_json = serde_json::to_string(&route_payload).unwrap();
        assert!(route_json.contains("\"domain\":\"routes\""));
        let route_deser: ObservationPayload = serde_json::from_str(&route_json).unwrap();
        assert_eq!(route_payload, route_deser);

        // 3. DNS payload
        let dns_payload = ObservationPayload::Dns(DnsObservationPayload {
            dns_servers: vec![DnsServerRecord {
                server_address: "1.1.1.1".to_string(),
                interface_name: Some("eth0".to_string()),
                is_ipv6: false,
                classification: IpClassification::PublicGlobal,
            }],
            search_domains: vec!["lan".to_string()],
            is_dynamic_dns_enabled: None,
        });
        let dns_json = serde_json::to_string(&dns_payload).unwrap();
        assert!(dns_json.contains("\"domain\":\"dns\""));
        let dns_deser: ObservationPayload = serde_json::from_str(&dns_json).unwrap();
        assert_eq!(dns_payload, dns_deser);

        // 4. Neighbors payload
        let neighbor_payload = ObservationPayload::Neighbors(NeighborObservationPayload {
            neighbors: vec![NeighborRecord {
                ip_address: "192.168.1.1".to_string(),
                mac_address_hash: Some(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                ),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                state: NeighborState::Reachable,
                is_ipv6: false,
                ip_classification: IpClassification::Private,
                is_router: Some(true),
            }],
        });
        let neighbor_json = serde_json::to_string(&neighbor_payload).unwrap();
        assert!(neighbor_json.contains("\"domain\":\"neighbors\""));
        let neighbor_deser: ObservationPayload = serde_json::from_str(&neighbor_json).unwrap();
        assert_eq!(neighbor_payload, neighbor_deser);
    }
}
