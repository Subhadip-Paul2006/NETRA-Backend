//! # In-Memory Network Topology Synthesis
//!
//! Provides deterministic in-memory synthesis of local network reachability,
//! active subnets, default gateways, DNS resolvers, and adjacent neighbors.
//!
//! **INVARIANTS**:
//! - Purely in-memory, deterministic synthesis (zero network IO, zero packet injection).
//! - All elements are deterministically sorted.
//! - Preserves provenance and confidence scoring.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::id::DeviceId;
use crate::network::ip::IpClassification;
use crate::observation::models::ConfidenceScore;
use crate::observation::payloads::{
    DnsObservationPayload, InterfaceObservationPayload, NeighborObservationPayload,
    RouteObservationPayload,
};

/// Topology node representing a local network interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopologyInterfaceNode {
    pub name: String,
    pub index: u32,
    pub is_up: bool,
    pub is_loopback: bool,
    pub ip_addresses: Vec<String>,
    pub mac_address_hash: Option<String>,
}

/// Topology node representing an active default gateway.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopologyGatewayNode {
    pub gateway_ip: String,
    pub interface_index: u32,
    pub interface_name: Option<String>,
    pub metric: u32,
    pub is_ipv6: bool,
}

/// Topology node representing a configured DNS resolver.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopologyDnsNode {
    pub server_ip: String,
    pub is_ipv6: bool,
    pub classification: IpClassification,
}

/// Topology node representing an adjacent Layer-2/Layer-3 network neighbor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopologyNeighborNode {
    pub ip_address: String,
    pub mac_address_hash: Option<String>,
    pub interface_name: Option<String>,
    pub state: String,
    pub classification: IpClassification,
    pub is_router: bool,
}

/// Synthesized local subnet descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopologySubnetRecord {
    pub network_cidr: String,
    pub interface_name: String,
    pub is_ipv6: bool,
    pub classification: IpClassification,
}

/// Normalized, deterministic snapshot of host network configuration and local topology.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkTopologySnapshot {
    pub schema_version: u32,
    pub device_id: DeviceId,
    pub generated_at: DateTime<Utc>,
    pub interfaces: Vec<TopologyInterfaceNode>,
    pub default_gateways: Vec<TopologyGatewayNode>,
    pub dns_resolvers: Vec<TopologyDnsNode>,
    pub neighbors: Vec<TopologyNeighborNode>,
    pub subnets: Vec<TopologySubnetRecord>,
    pub is_multi_homed: bool,
    pub confidence: ConfidenceScore,
    pub provenance_sources: Vec<String>,
}

/// In-memory builder for deterministic `NetworkTopologySnapshot`.
pub struct TopologyBuilder;

impl TopologyBuilder {
    pub fn build(
        device_id: DeviceId,
        interfaces_payload: Option<&InterfaceObservationPayload>,
        routes_payload: Option<&RouteObservationPayload>,
        dns_payload: Option<&DnsObservationPayload>,
        neighbors_payload: Option<&NeighborObservationPayload>,
    ) -> NetworkTopologySnapshot {
        let mut provenance_sources = Vec::new();

        // 1. Process Interfaces
        let mut interfaces = Vec::new();
        let mut subnets = Vec::new();
        let mut active_non_loopback_subnets = std::collections::HashSet::new();

        if let Some(payload) = interfaces_payload {
            provenance_sources.push("scanner.interfaces.v1".to_string());
            for iface in &payload.interfaces {
                let ips: Vec<String> = iface
                    .ip_addresses
                    .iter()
                    .map(|ip| ip.ip_address.clone())
                    .collect();

                let is_up = iface.oper_status == crate::observation::payloads::InterfaceStatus::Up;

                if is_up && !iface.is_loopback {
                    for ip_rec in &iface.ip_addresses {
                        if !ip_rec.classification.is_local_or_private()
                            && !ip_rec.classification.is_public()
                        {
                            continue;
                        }
                        let subnet_str = format!("{}/{}", ip_rec.ip_address, ip_rec.prefix_length);
                        subnets.push(TopologySubnetRecord {
                            network_cidr: subnet_str.clone(),
                            interface_name: iface.interface_name.clone(),
                            is_ipv6: ip_rec.is_ipv6,
                            classification: ip_rec.classification,
                        });
                        active_non_loopback_subnets.insert(iface.interface_index);
                    }
                }

                interfaces.push(TopologyInterfaceNode {
                    name: iface.interface_name.clone(),
                    index: iface.interface_index,
                    is_up,
                    is_loopback: iface.is_loopback,
                    ip_addresses: ips,
                    mac_address_hash: iface.mac_address_hash.clone(),
                });
            }
        }

        interfaces.sort_by_key(|i| i.index);
        subnets.sort_by(|a, b| a.network_cidr.cmp(&b.network_cidr));

        // 2. Process Routes & Default Gateways
        let mut default_gateways = Vec::new();
        if let Some(payload) = routes_payload {
            provenance_sources.push("scanner.routes.v1".to_string());
            for r in &payload.routes {
                if r.is_default_gateway {
                    if let Some(ref gw) = r.gateway_ip {
                        default_gateways.push(TopologyGatewayNode {
                            gateway_ip: gw.clone(),
                            interface_index: r.interface_index,
                            interface_name: r.interface_name.clone(),
                            metric: r.metric,
                            is_ipv6: r.is_ipv6,
                        });
                    }
                }
            }
        }
        default_gateways.sort_by_key(|g| (g.metric, g.gateway_ip.clone()));

        // 3. Process DNS
        let mut dns_resolvers = Vec::new();
        if let Some(payload) = dns_payload {
            provenance_sources.push("scanner.dns.v1".to_string());
            for d in &payload.dns_servers {
                dns_resolvers.push(TopologyDnsNode {
                    server_ip: d.server_address.clone(),
                    is_ipv6: d.is_ipv6,
                    classification: d.classification,
                });
            }
        }
        dns_resolvers.sort_by(|a, b| a.server_ip.cmp(&b.server_ip));

        // 4. Process Neighbors
        let mut neighbors = Vec::new();
        if let Some(payload) = neighbors_payload {
            provenance_sources.push("scanner.neighbors.v1".to_string());
            for n in &payload.neighbors {
                neighbors.push(TopologyNeighborNode {
                    ip_address: n.ip_address.clone(),
                    mac_address_hash: n.mac_address_hash.clone(),
                    interface_name: n.interface_name.clone(),
                    state: format!("{:?}", n.state),
                    classification: n.ip_classification,
                    is_router: n.is_router.unwrap_or(false),
                });
            }
        }
        neighbors.sort_by(|a, b| a.ip_address.cmp(&b.ip_address));

        // Multi-homed detection: > 1 active non-loopback interfaces with assigned networks
        let is_multi_homed = active_non_loopback_subnets.len() > 1;

        let confidence = if provenance_sources.len() >= 4 {
            ConfidenceScore::KERNEL_AUTHORITATIVE
        } else if !provenance_sources.is_empty() {
            ConfidenceScore::SYSTEM_TABLE
        } else {
            ConfidenceScore::HEURISTIC
        };

        NetworkTopologySnapshot {
            schema_version: 1,
            device_id,
            generated_at: Utc::now(),
            interfaces,
            default_gateways,
            dns_resolvers,
            neighbors,
            subnets,
            is_multi_homed,
            confidence,
            provenance_sources,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::payloads::*;

    #[test]
    fn test_topology_builder_synthesis() {
        let device_id = DeviceId::new();

        let iface_payload = InterfaceObservationPayload {
            interfaces: vec![
                InterfaceRecord {
                    interface_name: "eth0".to_string(),
                    friendly_name: Some("Ethernet 1".to_string()),
                    interface_index: 2,
                    mac_address_hash: Some("abcdef1234567890".to_string()),
                    interface_type: InterfaceType::Ethernet,
                    oper_status: InterfaceStatus::Up,
                    ip_addresses: vec![IpNetworkRecord {
                        ip_address: "192.168.1.50".to_string(),
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
                },
                InterfaceRecord {
                    interface_name: "lo".to_string(),
                    friendly_name: Some("Loopback".to_string()),
                    interface_index: 1,
                    mac_address_hash: None,
                    interface_type: InterfaceType::Loopback,
                    oper_status: InterfaceStatus::Up,
                    ip_addresses: vec![IpNetworkRecord {
                        ip_address: "127.0.0.1".to_string(),
                        prefix_length: 8,
                        is_ipv6: false,
                        classification: IpClassification::Loopback,
                        broadcast_address: None,
                    }],
                    mtu: 65536,
                    is_loopback: true,
                    is_point_to_point: false,
                    is_dhcp_enabled: None,
                    is_virtual: false,
                },
            ],
        };

        let routes_payload = RouteObservationPayload {
            routes: vec![RouteRecord {
                destination_cidr: "0.0.0.0/0".to_string(),
                gateway_ip: Some("192.168.1.1".to_string()),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                metric: 10,
                is_ipv6: false,
                is_default_gateway: true,
                route_type: RouteType::Remote,
            }],
            default_gateways: vec!["192.168.1.1".to_string()],
        };

        let dns_payload = DnsObservationPayload {
            dns_servers: vec![DnsServerRecord {
                server_address: "1.1.1.1".to_string(),
                interface_name: Some("eth0".to_string()),
                is_ipv6: false,
                classification: IpClassification::PublicGlobal,
            }],
            search_domains: vec!["localdomain".to_string()],
            is_dynamic_dns_enabled: None,
        };

        let neighbor_payload = NeighborObservationPayload {
            neighbors: vec![NeighborRecord {
                ip_address: "192.168.1.1".to_string(),
                mac_address_hash: Some("1122334455667788".to_string()),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                state: NeighborState::Reachable,
                is_ipv6: false,
                ip_classification: IpClassification::Private,
                is_router: Some(true),
            }],
        };

        let snapshot = TopologyBuilder::build(
            device_id.clone(),
            Some(&iface_payload),
            Some(&routes_payload),
            Some(&dns_payload),
            Some(&neighbor_payload),
        );

        assert_eq!(snapshot.device_id, device_id);
        assert_eq!(snapshot.interfaces.len(), 2);
        assert_eq!(snapshot.interfaces[0].name, "lo"); // Sorted by index: 1 before 2
        assert_eq!(snapshot.interfaces[1].name, "eth0");
        assert_eq!(snapshot.default_gateways.len(), 1);
        assert_eq!(snapshot.default_gateways[0].gateway_ip, "192.168.1.1");
        assert_eq!(snapshot.dns_resolvers.len(), 1);
        assert_eq!(snapshot.neighbors.len(), 1);
        assert_eq!(snapshot.neighbors[0].ip_address, "192.168.1.1");
        assert_eq!(snapshot.subnets.len(), 1);
        assert_eq!(snapshot.subnets[0].network_cidr, "192.168.1.50/24");
        assert!(!snapshot.is_multi_homed);
        assert_eq!(snapshot.confidence, ConfidenceScore::KERNEL_AUTHORITATIVE);
    }
}
