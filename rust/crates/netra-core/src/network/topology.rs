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
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::id::DeviceId;
use crate::network::ip::IpClassification;
use crate::observation::models::{ConfidenceScore, Observation, PrivilegeStatus};
use crate::observation::payloads::{
    DnsObservationPayload, InterfaceObservationPayload, NeighborObservationPayload,
    ObservationPayload, RouteObservationPayload,
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

// =============================================================================
// PHASE 8.6: Typed Topology Correlation Edges
// =============================================================================

/// Typed kind of directed relationship between two topology nodes.
///
/// All edge semantics are provable from data already present in
/// `NetworkTopologySnapshot` — no external queries or active discovery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TopologyEdgeKind {
    /// Interface is the confirmed egress path for a default gateway entry.
    InterfaceHasGateway,
    /// Interface has this IP neighbor in its observed ARP/NDP cache.
    InterfaceHasNeighbor,
    /// Interface hosts this active IP subnet (from IP address + prefix).
    InterfaceHostsSubnet,
    /// A neighbor cache entry matches the IP of a default gateway.
    NeighborIsGateway,
    /// Gateway IP address falls within a locally active subnet CIDR.
    GatewayOnSubnet,
    /// DNS resolver IP address falls within a locally active subnet CIDR.
    /// Does NOT assert interface ownership — only CIDR containment is provable
    /// from existing observation data.
    DnsOnSubnet,
}

/// A deterministic directed relationship between two topology nodes,
/// identified by stable string keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopologyCorrelationEdge {
    pub kind: TopologyEdgeKind,
    /// Stable key of the source topology node (e.g. `"interface:eth0"`).
    pub from_key: String,
    /// Stable key of the destination topology node (e.g. `"gateway:192.168.1.1"`).
    pub to_key: String,
}

// =============================================================================
// PHASE 8.6: CIDR Containment (std::net only — no ipnet dependency)
// =============================================================================

/// Returns `true` if `ip_str` falls within the CIDR prefix described by `cidr_str`.
///
/// Supports IPv4 and IPv6. Handles prefix length 0 (all-match) and 32/128
/// (exact match). Malformed inputs or address-family mismatches return `false`.
fn ip_in_cidr(ip_str: &str, cidr_str: &str) -> bool {
    let slash = match cidr_str.rfind('/') {
        Some(p) => p,
        None => return false,
    };
    let addr_part = &cidr_str[..slash];
    let prefix_part = &cidr_str[slash + 1..];

    let prefix_len: u8 = match prefix_part.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    let ip: IpAddr = match ip_str.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let cidr_addr: IpAddr = match addr_part.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    match (ip, cidr_addr) {
        (IpAddr::V4(ip4), IpAddr::V4(cidr4)) => {
            if prefix_len > 32 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let shift = 32 - u32::from(prefix_len);
            let mask = (!0u32).wrapping_shl(shift);
            let ip_bits = u32::from(ip4);
            let cidr_bits = u32::from(cidr4);
            (ip_bits & mask) == (cidr_bits & mask)
        }
        (IpAddr::V6(ip6), IpAddr::V6(cidr6)) => {
            if prefix_len > 128 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let shift = 128 - u32::from(prefix_len);
            let mask = (!0u128).wrapping_shl(shift);
            let ip_bits = u128::from(ip6);
            let cidr_bits = u128::from(cidr6);
            (ip_bits & mask) == (cidr_bits & mask)
        }
        _ => false, // address-family mismatch
    }
}

// =============================================================================
// PHASE 8.6: TopologyCorrelator
// =============================================================================

/// Pure in-memory correlator that derives typed `TopologyCorrelationEdge`
/// relationships from an existing `NetworkTopologySnapshot`.
///
/// **Invariants:**
/// - Zero network IO, zero filesystem IO, zero subprocess execution.
/// - Output is fully deterministic given the same input snapshot.
/// - Only relationships provable from data already in the snapshot are emitted.
pub struct TopologyCorrelator;

impl TopologyCorrelator {
    /// Derives all correlation edges from a synthesized topology snapshot.
    ///
    /// Edges are sorted by `(kind, from_key, to_key)` to guarantee a
    /// deterministic ordering, which is required for stable evidence hashing.
    pub fn correlate(snapshot: &NetworkTopologySnapshot) -> Vec<TopologyCorrelationEdge> {
        let mut edges: Vec<TopologyCorrelationEdge> = Vec::new();

        // Build an interface lookup by index (for gateway correlation).
        let interface_by_index: HashMap<u32, &TopologyInterfaceNode> =
            snapshot.interfaces.iter().map(|i| (i.index, i)).collect();

        // ── InterfaceHostsSubnet ──────────────────────────────────────────────
        for subnet in &snapshot.subnets {
            edges.push(TopologyCorrelationEdge {
                kind: TopologyEdgeKind::InterfaceHostsSubnet,
                from_key: format!("interface:{}", subnet.interface_name.to_lowercase()),
                to_key: format!("subnet:{}", subnet.network_cidr),
            });
        }

        // ── InterfaceHasGateway ───────────────────────────────────────────────
        for gw in &snapshot.default_gateways {
            let iface_key = if let Some(ref name) = gw.interface_name {
                format!("interface:{}", name.to_lowercase())
            } else if let Some(iface) = interface_by_index.get(&gw.interface_index) {
                format!("interface:{}", iface.name.to_lowercase())
            } else {
                format!("interface:idx:{}", gw.interface_index)
            };
            edges.push(TopologyCorrelationEdge {
                kind: TopologyEdgeKind::InterfaceHasGateway,
                from_key: iface_key,
                to_key: format!("gateway:{}", gw.gateway_ip),
            });
        }

        // ── InterfaceHasNeighbor ──────────────────────────────────────────────
        for neighbor in &snapshot.neighbors {
            if let Some(ref iface_name) = neighbor.interface_name {
                edges.push(TopologyCorrelationEdge {
                    kind: TopologyEdgeKind::InterfaceHasNeighbor,
                    from_key: format!("interface:{}", iface_name.to_lowercase()),
                    to_key: format!("neighbor:{}", neighbor.ip_address),
                });
            }
        }

        // Build neighbor IP set for NeighborIsGateway.
        let neighbor_ips: HashSet<&str> = snapshot
            .neighbors
            .iter()
            .map(|n| n.ip_address.as_str())
            .collect();

        // ── NeighborIsGateway + GatewayOnSubnet ───────────────────────────────
        for gw in &snapshot.default_gateways {
            let gw_key = format!("gateway:{}", gw.gateway_ip);

            // NeighborIsGateway: gateway IP present in neighbor cache
            if neighbor_ips.contains(gw.gateway_ip.as_str()) {
                edges.push(TopologyCorrelationEdge {
                    kind: TopologyEdgeKind::NeighborIsGateway,
                    from_key: format!("neighbor:{}", gw.gateway_ip),
                    to_key: gw_key.clone(),
                });
            }

            // GatewayOnSubnet: gateway IP falls within a local subnet CIDR
            for subnet in &snapshot.subnets {
                if ip_in_cidr(&gw.gateway_ip, &subnet.network_cidr) {
                    edges.push(TopologyCorrelationEdge {
                        kind: TopologyEdgeKind::GatewayOnSubnet,
                        from_key: gw_key.clone(),
                        to_key: format!("subnet:{}", subnet.network_cidr),
                    });
                }
            }
        }

        // ── DnsOnSubnet ───────────────────────────────────────────────────────
        // Semantics: DNS resolver IP falls within a locally active subnet CIDR.
        // Interface ownership is NOT asserted (not provable in all cases).
        for dns in &snapshot.dns_resolvers {
            let dns_key = format!("dns:{}", dns.server_ip);
            for subnet in &snapshot.subnets {
                if ip_in_cidr(&dns.server_ip, &subnet.network_cidr) {
                    edges.push(TopologyCorrelationEdge {
                        kind: TopologyEdgeKind::DnsOnSubnet,
                        from_key: dns_key.clone(),
                        to_key: format!("subnet:{}", subnet.network_cidr),
                    });
                }
            }
        }

        // Deterministic sort: (kind, from_key, to_key).
        edges.sort_by(|a, b| {
            a.kind
                .cmp(&b.kind)
                .then_with(|| a.from_key.cmp(&b.from_key))
                .then_with(|| a.to_key.cmp(&b.to_key))
        });

        edges
    }
}

// =============================================================================
// PHASE 8.6: TopologyObservationPayload
// =============================================================================

/// The scanner ID constant for topology synthesis.
pub const TOPOLOGY_SCANNER_ID: &str = "scanner.topology.v1";

/// Expected network scanner IDs that feed into topology synthesis.
pub const NETWORK_SCANNER_IDS: [&str; 4] = [
    "scanner.interfaces.v1",
    "scanner.routes.v1",
    "scanner.dns.v1",
    "scanner.neighbors.v1",
];

/// Observation payload wrapping the synthesized in-memory network topology.
///
/// This is **derived** data — synthesized from 4 network scanner observations
/// already persisted in Transaction A. It is not independently observable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TopologyObservationPayload {
    /// The synthesized deterministic topology snapshot.
    pub snapshot: NetworkTopologySnapshot,
    /// Typed, deterministically sorted correlation edges between topology nodes.
    pub edges: Vec<TopologyCorrelationEdge>,
    /// Scanner IDs expected but absent from the scan cycle (timeout / panic).
    pub missing_sources: Vec<String>,
    /// Scanner IDs present but with `Partial` or `Unsupported` privilege status.
    /// These sources may contribute partial data (Partial) or no data (Unsupported)
    /// but do NOT count as usable for confidence scoring.
    pub partial_sources: Vec<String>,
}

// =============================================================================
// PHASE 8.6: TopologyExtractor
// =============================================================================

/// Extracts the 4 network observation payloads from a completed scan cycle
/// observation slice and computes confidence and provenance metadata.
///
/// **Invariants:**
/// - Zero OS queries, zero network IO, zero filesystem IO.
/// - Operates only on observations already produced in the current scan cycle.
/// - No unsafe code, no reflection.
pub struct TopologyExtractor;

impl TopologyExtractor {
    /// Extracts the 4 typed network payloads from `observations` and classifies
    /// sources as usable, partial, unsupported, or missing.
    ///
    /// Returns:
    /// - Four `Option<Payload>` in order: interfaces, routes, dns, neighbors.
    /// - `missing_sources`: scanner IDs from the expected set that produced no observation.
    /// - `partial_sources`: scanner IDs present but with `Partial` or `Unsupported` status.
    #[allow(clippy::type_complexity)]
    pub fn extract_from_observations(
        observations: &[Observation],
    ) -> (
        Option<InterfaceObservationPayload>,
        Option<RouteObservationPayload>,
        Option<DnsObservationPayload>,
        Option<NeighborObservationPayload>,
        Vec<String>, // missing_sources
        Vec<String>, // partial_sources
    ) {
        let mut iface_payload: Option<InterfaceObservationPayload> = None;
        let mut route_payload: Option<RouteObservationPayload> = None;
        let mut dns_payload: Option<DnsObservationPayload> = None;
        let mut neighbor_payload: Option<NeighborObservationPayload> = None;
        let mut partial_sources: Vec<String> = Vec::new();
        let mut seen_ids: HashSet<String> = HashSet::new();

        for obs in observations {
            let scanner_id = obs.scanner_id.as_str();

            if NETWORK_SCANNER_IDS.contains(&scanner_id) {
                seen_ids.insert(obs.scanner_id.clone());

                // Classify privilege level for this network scanner.
                let is_usable = matches!(obs.privilege_level, PrivilegeStatus::Available);
                if !is_usable {
                    partial_sources.push(obs.scanner_id.clone());
                }
            }

            // Extract payloads regardless of privilege level.
            // Partial sources contribute their (possibly partial) data.
            // Unsupported sources produce structurally empty payloads (all Vecs empty).
            match &obs.payload {
                ObservationPayload::Interfaces(p) if scanner_id == "scanner.interfaces.v1" => {
                    iface_payload = Some(p.clone());
                }
                ObservationPayload::Routes(p) if scanner_id == "scanner.routes.v1" => {
                    route_payload = Some(p.clone());
                }
                ObservationPayload::Dns(p) if scanner_id == "scanner.dns.v1" => {
                    dns_payload = Some(p.clone());
                }
                ObservationPayload::Neighbors(p) if scanner_id == "scanner.neighbors.v1" => {
                    neighbor_payload = Some(p.clone());
                }
                _ => {}
            }
        }

        // Identify scanner IDs from the expected set that produced no observation.
        let missing_sources: Vec<String> = NETWORK_SCANNER_IDS
            .iter()
            .filter(|id| !seen_ids.contains(**id))
            .map(|id| id.to_string())
            .collect();

        (
            iface_payload,
            route_payload,
            dns_payload,
            neighbor_payload,
            missing_sources,
            partial_sources,
        )
    }

    /// Computes the topology `ConfidenceScore` based on the count of **usable**
    /// sources — observations from the expected 4 network scanners with
    /// `PrivilegeStatus::Available`.
    ///
    /// | Usable count | ConfidenceScore           |
    /// |---|---|
    /// | 4 | `KERNEL_AUTHORITATIVE` (1.0) |
    /// | 3 | `SYSTEM_TABLE` (0.9)         |
    /// | 2 | `UNPRIVILEGED_PARTIAL` (0.7) |
    /// | 1 | `HEURISTIC` (0.5)            |
    /// | 0 | `HEURISTIC` (0.5)            |
    pub fn compute_confidence(observations: &[Observation]) -> ConfidenceScore {
        let usable_count = observations
            .iter()
            .filter(|obs| {
                NETWORK_SCANNER_IDS.contains(&obs.scanner_id.as_str())
                    && matches!(obs.privilege_level, PrivilegeStatus::Available)
            })
            .count();

        match usable_count {
            4 => ConfidenceScore::KERNEL_AUTHORITATIVE,
            3 => ConfidenceScore::SYSTEM_TABLE,
            2 => ConfidenceScore::UNPRIVILEGED_PARTIAL,
            _ => ConfidenceScore::HEURISTIC,
        }
    }

    /// Derives the `PrivilegeStatus` for the topology observation envelope.
    ///
    /// - `Available` if at least one usable (Available) network source exists.
    /// - `Partial` if sources were present but none were usable.
    /// - `Unsupported` if no expected scanner observations were present at all.
    pub fn derive_privilege(observations: &[Observation]) -> PrivilegeStatus {
        let has_usable = observations.iter().any(|obs| {
            NETWORK_SCANNER_IDS.contains(&obs.scanner_id.as_str())
                && matches!(obs.privilege_level, PrivilegeStatus::Available)
        });
        if has_usable {
            return PrivilegeStatus::Available;
        }

        let has_any = observations
            .iter()
            .any(|obs| NETWORK_SCANNER_IDS.contains(&obs.scanner_id.as_str()));
        if has_any {
            PrivilegeStatus::Partial
        } else {
            PrivilegeStatus::Unsupported
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

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

    #[test]
    fn test_ip_in_cidr_ipv4() {
        // Basic containment
        assert!(ip_in_cidr("192.168.1.50", "192.168.1.0/24"));
        assert!(ip_in_cidr("192.168.1.1", "192.168.1.0/24"));
        assert!(ip_in_cidr("192.168.1.255", "192.168.1.0/24"));
        // Outside range
        assert!(!ip_in_cidr("192.168.2.1", "192.168.1.0/24"));
        // Exact match (/32)
        assert!(ip_in_cidr("10.0.0.1", "10.0.0.1/32"));
        assert!(!ip_in_cidr("10.0.0.2", "10.0.0.1/32"));
        // All-match prefix 0
        assert!(ip_in_cidr("1.2.3.4", "0.0.0.0/0"));
        // Address-family mismatch
        assert!(!ip_in_cidr("192.168.1.1", "fe80::/10"));
        // Malformed CIDR
        assert!(!ip_in_cidr("192.168.1.1", "not-a-cidr"));
        assert!(!ip_in_cidr("192.168.1.1", "192.168.1.0/99"));
    }

    #[test]
    fn test_ip_in_cidr_ipv6() {
        assert!(ip_in_cidr("fe80::1", "fe80::/10"));
        assert!(ip_in_cidr("::1", "::1/128"));
        assert!(!ip_in_cidr("::2", "::1/128"));
        assert!(ip_in_cidr("2001:db8::1", "2001:db8::/32"));
        assert!(!ip_in_cidr("2001:db9::1", "2001:db8::/32"));
        // All-match prefix 0
        assert!(ip_in_cidr("::1", "::/0"));
        // Address-family mismatch
        assert!(!ip_in_cidr("::1", "192.168.1.0/24"));
    }

    #[test]
    fn test_topology_correlator_basic_edges() {
        let device_id = DeviceId::new();

        // Snapshot with interface eth0 + gateway 192.168.1.1 + neighbor 192.168.1.1
        let snapshot = NetworkTopologySnapshot {
            schema_version: 1,
            device_id,
            generated_at: Utc::now(),
            interfaces: vec![TopologyInterfaceNode {
                name: "eth0".to_string(),
                index: 2,
                is_up: true,
                is_loopback: false,
                ip_addresses: vec!["192.168.1.50".to_string()],
                mac_address_hash: None,
            }],
            default_gateways: vec![TopologyGatewayNode {
                gateway_ip: "192.168.1.1".to_string(),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                metric: 10,
                is_ipv6: false,
            }],
            dns_resolvers: vec![TopologyDnsNode {
                server_ip: "192.168.1.1".to_string(),
                is_ipv6: false,
                classification: IpClassification::Private,
            }],
            neighbors: vec![TopologyNeighborNode {
                ip_address: "192.168.1.1".to_string(),
                mac_address_hash: None,
                interface_name: Some("eth0".to_string()),
                state: "Reachable".to_string(),
                classification: IpClassification::Private,
                is_router: true,
            }],
            subnets: vec![TopologySubnetRecord {
                network_cidr: "192.168.1.50/24".to_string(),
                interface_name: "eth0".to_string(),
                is_ipv6: false,
                classification: IpClassification::Private,
            }],
            is_multi_homed: false,
            confidence: ConfidenceScore::KERNEL_AUTHORITATIVE,
            provenance_sources: vec![
                "scanner.interfaces.v1".to_string(),
                "scanner.routes.v1".to_string(),
                "scanner.dns.v1".to_string(),
                "scanner.neighbors.v1".to_string(),
            ],
        };

        let edges = TopologyCorrelator::correlate(&snapshot);

        // Verify all expected edge kinds are present
        let kinds: HashSet<TopologyEdgeKind> = edges.iter().map(|e| e.kind.clone()).collect();
        assert!(kinds.contains(&TopologyEdgeKind::InterfaceHostsSubnet));
        assert!(kinds.contains(&TopologyEdgeKind::InterfaceHasGateway));
        assert!(kinds.contains(&TopologyEdgeKind::InterfaceHasNeighbor));
        assert!(kinds.contains(&TopologyEdgeKind::NeighborIsGateway));
        assert!(kinds.contains(&TopologyEdgeKind::GatewayOnSubnet));
        assert!(kinds.contains(&TopologyEdgeKind::DnsOnSubnet));

        // Verify deterministic ordering: edges must be sorted by (kind, from_key, to_key)
        let mut sorted = edges.clone();
        sorted.sort_by(|a, b| {
            a.kind
                .cmp(&b.kind)
                .then_with(|| a.from_key.cmp(&b.from_key))
                .then_with(|| a.to_key.cmp(&b.to_key))
        });
        assert_eq!(
            edges, sorted,
            "correlate() output must be deterministically sorted"
        );
    }

    #[test]
    fn test_topology_correlator_external_dns_no_edge() {
        let device_id = DeviceId::new();
        let snapshot = NetworkTopologySnapshot {
            schema_version: 1,
            device_id,
            generated_at: Utc::now(),
            interfaces: vec![],
            default_gateways: vec![],
            dns_resolvers: vec![TopologyDnsNode {
                server_ip: "8.8.8.8".to_string(),
                is_ipv6: false,
                classification: IpClassification::PublicGlobal,
            }],
            neighbors: vec![],
            subnets: vec![TopologySubnetRecord {
                network_cidr: "192.168.1.0/24".to_string(),
                interface_name: "eth0".to_string(),
                is_ipv6: false,
                classification: IpClassification::Private,
            }],
            is_multi_homed: false,
            confidence: ConfidenceScore::HEURISTIC,
            provenance_sources: vec![],
        };

        let edges = TopologyCorrelator::correlate(&snapshot);
        let dns_edges: Vec<_> = edges
            .iter()
            .filter(|e| e.kind == TopologyEdgeKind::DnsOnSubnet)
            .collect();
        assert!(
            dns_edges.is_empty(),
            "External DNS server 8.8.8.8 must not produce a DnsOnSubnet edge"
        );
    }
}
