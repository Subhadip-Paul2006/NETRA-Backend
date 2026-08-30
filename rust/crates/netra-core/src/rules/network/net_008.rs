//! # Rule NET-008: Host Simultaneously Attached to Public and Private Networks
//!
//! Evaluates whether the host is simultaneously attached to both public globally routable
//! networks (`IpClassification::PublicGlobal`) and internal private networks
//! (`IpClassification::Private` / RFC 1918) across distinct eligible physical network adapters.
//!
//! # Strict Observational Boundary
//! - **OBSERVED**: Concurrent presence of PublicGlobal and Private addresses across eligible
//!   physical network interfaces.
//! - **NOT PROVEN**: Telemetry does NOT prove whether Internet reachability is active,
//!   whether IP forwarding/bridging is enabled, or whether an actual perimeter exposure exists.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::network::topology::TopologyInterfaceNode;
use crate::network::IpClassification;
use crate::observation::{Observation, ObservationType, TargetDescriptor};
use crate::rules::network::common::{
    extract_topology_payload, format_discriminator, GuardrailDecision, NetworkConfidenceGuardrail,
};
use crate::rules::traits::{FindingRule, RawFinding};
use crate::storage::FindingSeverity;

/// Rule implementation for NET-008: Host Simultaneously Attached to Public and Private Networks.
pub struct Net008MultiHomedPublicPrivateRule {
    guardrail: NetworkConfidenceGuardrail,
}

impl Net008MultiHomedPublicPrivateRule {
    /// Creates a new instance of `Net008MultiHomedPublicPrivateRule` with standard guardrails.
    pub fn new() -> Self {
        Self {
            guardrail: NetworkConfidenceGuardrail::standard(
                &["scanner.interfaces.v1", "scanner.routes.v1"],
                FindingSeverity::Low,
            ),
        }
    }

    /// Determines if a network interface is an eligible physical (non-virtual, non-loopback) adapter.
    fn is_eligible_physical_interface(iface: &TopologyInterfaceNode) -> bool {
        if !iface.is_up || iface.is_loopback {
            return false;
        }

        let name_lower = iface.name.to_lowercase();
        let virtual_patterns = [
            "docker",
            "veth",
            "wsl",
            "vethernet",
            "br-",
            "virbr",
            "tun",
            "tap",
            "wg",
            "ppp",
            "tailscale",
            "dummy",
            "lo",
            "hyper-v",
            "bridge",
        ];

        for pat in &virtual_patterns {
            if name_lower.contains(pat) {
                return false;
            }
        }

        true
    }
}

impl Default for Net008MultiHomedPublicPrivateRule {
    fn default() -> Self {
        Self::new()
    }
}

impl FindingRule for Net008MultiHomedPublicPrivateRule {
    fn rule_id(&self) -> &'static str {
        "NET-008-MULTI-HOMED-PUBLIC-PRIVATE"
    }

    fn version(&self) -> u32 {
        1
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Topology
    }

    fn default_severity(&self) -> FindingSeverity {
        FindingSeverity::Low
    }

    fn evaluate(&self, obs: &Observation) -> Vec<RawFinding> {
        let mut findings = Vec::new();

        // 1. Guardrail evaluation
        let effective_severity = match self.guardrail.evaluate(obs, self.default_severity()) {
            GuardrailDecision::Proceed(sev) => sev,
            GuardrailDecision::Suppress => return findings,
        };

        // 2. Extract topology payload
        let topo = match extract_topology_payload(obs) {
            Some(p) => p,
            None => return findings,
        };

        let mut public_interfaces: BTreeMap<String, String> = BTreeMap::new();
        let mut private_interfaces: BTreeMap<String, String> = BTreeMap::new();

        // 3. Classify eligible interfaces
        for iface in &topo.snapshot.interfaces {
            if !Self::is_eligible_physical_interface(iface) {
                continue;
            }

            // Check raw IP address list directly
            for ip_str in &iface.ip_addresses {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    let classification = IpClassification::classify(&ip);
                    if classification == IpClassification::PublicGlobal {
                        public_interfaces
                            .entry(iface.name.clone())
                            .or_insert_with(|| ip_str.clone());
                    } else if classification == IpClassification::Private {
                        private_interfaces
                            .entry(iface.name.clone())
                            .or_insert_with(|| ip_str.clone());
                    }
                }
            }

            // Also check subnets attached to this interface
            for subnet in &topo.snapshot.subnets {
                if subnet.interface_name == iface.name {
                    if subnet.classification == IpClassification::PublicGlobal {
                        public_interfaces
                            .entry(iface.name.clone())
                            .or_insert_with(|| subnet.network_cidr.clone());
                    } else if subnet.classification == IpClassification::Private {
                        private_interfaces
                            .entry(iface.name.clone())
                            .or_insert_with(|| subnet.network_cidr.clone());
                    }
                }
            }
        }

        // 4. Generate finding if at least one Public and at least one Private interface exist on different physical adapters
        for (pub_iface, pub_ip) in &public_interfaces {
            for (priv_iface, priv_ip) in &private_interfaces {
                if pub_iface == priv_iface {
                    continue;
                }

                let target = TargetDescriptor::Host {
                    hostname: match &obs.target {
                        TargetDescriptor::Host { hostname } => hostname.clone(),
                        _ => "host".to_string(),
                    },
                };

                let discriminator =
                    format_discriminator("MULTI_HOMED_PUB_PRIV", &[pub_iface, priv_iface]);

                let title =
                    "Host Simultaneously Attached to Public and Private Networks".to_string();
                let description = format!(
                    "The host is observed to be simultaneously connected to a public network on interface '{}' ({}) and an internal private network on interface '{}' ({}). This multi-homed configuration warrants administrative review to ensure intended network segmentation and routing boundaries are maintained.",
                    pub_iface, pub_ip, priv_iface, priv_ip
                );
                let remediation = "Review intended network architecture, routing tables, firewall filtering, and IP forwarding policies to verify whether multi-homing across public and private network zones is expected.".to_string();

                let evidence = serde_json::json!({
                    "public_interface": pub_iface,
                    "public_ip": pub_ip,
                    "private_interface": priv_iface,
                    "private_ip": priv_ip,
                    "reason": "Observed concurrent active physical network interface attachments on both public and RFC 1918 private subnets."
                });

                findings.push(RawFinding {
                    title,
                    description,
                    severity: effective_severity,
                    target,
                    discriminator,
                    remediation_guidance: Some(remediation),
                    raw_evidence: evidence,
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::DeviceId;
    use crate::network::topology::{
        NetworkTopologySnapshot, TopologyGatewayNode, TopologyObservationPayload,
        TopologySubnetRecord,
    };
    use crate::observation::models::{ConfidenceScore, PrivilegeStatus, SensitivityLevel};
    use crate::observation::payloads::ObservationPayload;
    use chrono::Utc;

    fn make_topology_obs(
        interfaces: Vec<TopologyInterfaceNode>,
        subnets: Vec<TopologySubnetRecord>,
        privilege: PrivilegeStatus,
        confidence: ConfidenceScore,
        missing_sources: Vec<String>,
        partial_sources: Vec<String>,
    ) -> Observation {
        let snapshot = NetworkTopologySnapshot {
            schema_version: 1,
            device_id: DeviceId::new(),
            generated_at: Utc::now(),
            interfaces,
            default_gateways: vec![TopologyGatewayNode {
                gateway_ip: "192.168.1.1".to_string(),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                metric: 10,
                is_ipv6: false,
            }],
            dns_resolvers: vec![],
            neighbors: vec![],
            subnets,
            is_multi_homed: false,
            confidence,
            provenance_sources: vec![
                "scanner.interfaces.v1".to_string(),
                "scanner.routes.v1".to_string(),
            ],
        };

        let topo_payload = TopologyObservationPayload {
            snapshot,
            edges: vec![],
            missing_sources,
            partial_sources,
        };

        Observation::new(
            DeviceId::new(),
            "scanner.topology.v1",
            ObservationType::Topology,
            TargetDescriptor::Host {
                hostname: "test-host".to_string(),
            },
            10,
            privilege,
            confidence,
            SensitivityLevel::Internal,
            ObservationPayload::Topology(topo_payload),
        )
        .unwrap()
    }

    #[test]
    fn test_net008_metadata_and_domain() {
        let rule = Net008MultiHomedPublicPrivateRule::new();
        assert_eq!(rule.rule_id(), "NET-008-MULTI-HOMED-PUBLIC-PRIVATE");
        assert_eq!(rule.version(), 1);
        assert_eq!(rule.domain(), ObservationType::Topology);
        assert_eq!(rule.default_severity(), FindingSeverity::Low);
    }

    #[test]
    fn test_net008_single_interface_clean() {
        let rule = Net008MultiHomedPublicPrivateRule::new();
        let obs = make_topology_obs(
            vec![TopologyInterfaceNode {
                name: "eth0".to_string(),
                index: 2,
                is_up: true,
                is_loopback: false,
                ip_addresses: vec!["192.168.1.100".to_string()],
                mac_address_hash: None,
            }],
            vec![TopologySubnetRecord {
                network_cidr: "192.168.1.0/24".to_string(),
                interface_name: "eth0".to_string(),
                is_ipv6: false,
                classification: IpClassification::Private,
            }],
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            vec![],
            vec![],
        );

        let findings = rule.evaluate(&obs);
        assert!(findings.is_empty(), "Single interface must evaluate clean");
    }

    #[test]
    fn test_net008_multiple_private_interfaces_clean() {
        let rule = Net008MultiHomedPublicPrivateRule::new();
        let obs = make_topology_obs(
            vec![
                TopologyInterfaceNode {
                    name: "eth0".to_string(),
                    index: 2,
                    is_up: true,
                    is_loopback: false,
                    ip_addresses: vec!["192.168.1.100".to_string()],
                    mac_address_hash: None,
                },
                TopologyInterfaceNode {
                    name: "eth1".to_string(),
                    index: 3,
                    is_up: true,
                    is_loopback: false,
                    ip_addresses: vec!["10.0.0.50".to_string()],
                    mac_address_hash: None,
                },
            ],
            vec![
                TopologySubnetRecord {
                    network_cidr: "192.168.1.0/24".to_string(),
                    interface_name: "eth0".to_string(),
                    is_ipv6: false,
                    classification: IpClassification::Private,
                },
                TopologySubnetRecord {
                    network_cidr: "10.0.0.0/24".to_string(),
                    interface_name: "eth1".to_string(),
                    is_ipv6: false,
                    classification: IpClassification::Private,
                },
            ],
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            vec![],
            vec![],
        );

        let findings = rule.evaluate(&obs);
        assert!(
            findings.is_empty(),
            "Multiple private subnets (no public interface) must evaluate clean"
        );
    }

    #[test]
    fn test_net008_physical_and_docker_wsl_virtual_clean() {
        let rule = Net008MultiHomedPublicPrivateRule::new();
        let obs = make_topology_obs(
            vec![
                TopologyInterfaceNode {
                    name: "eth0".to_string(),
                    index: 2,
                    is_up: true,
                    is_loopback: false,
                    ip_addresses: vec!["93.184.216.34".to_string()],
                    mac_address_hash: None,
                },
                TopologyInterfaceNode {
                    name: "docker0".to_string(),
                    index: 3,
                    is_up: true,
                    is_loopback: false,
                    ip_addresses: vec!["172.17.0.1".to_string()],
                    mac_address_hash: None,
                },
                TopologyInterfaceNode {
                    name: "vEthernet (WSL)".to_string(),
                    index: 4,
                    is_up: true,
                    is_loopback: false,
                    ip_addresses: vec!["172.28.0.1".to_string()],
                    mac_address_hash: None,
                },
            ],
            vec![
                TopologySubnetRecord {
                    network_cidr: "93.184.216.0/24".to_string(),
                    interface_name: "eth0".to_string(),
                    is_ipv6: false,
                    classification: IpClassification::PublicGlobal,
                },
                TopologySubnetRecord {
                    network_cidr: "172.17.0.0/16".to_string(),
                    interface_name: "docker0".to_string(),
                    is_ipv6: false,
                    classification: IpClassification::Private,
                },
                TopologySubnetRecord {
                    network_cidr: "172.28.0.0/16".to_string(),
                    interface_name: "vEthernet (WSL)".to_string(),
                    is_ipv6: false,
                    classification: IpClassification::Private,
                },
            ],
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            vec![],
            vec![],
        );

        let findings = rule.evaluate(&obs);
        assert!(
            findings.is_empty(),
            "Virtual adapters (Docker, WSL) must be excluded from multi-homing alerts"
        );
    }

    #[test]
    fn test_net008_documentation_address_space_clean() {
        let rule = Net008MultiHomedPublicPrivateRule::new();
        // 198.51.100.25 is TEST-NET-2 (Documentation space), not PublicGlobal
        let obs = make_topology_obs(
            vec![
                TopologyInterfaceNode {
                    name: "eth0".to_string(),
                    index: 2,
                    is_up: true,
                    is_loopback: false,
                    ip_addresses: vec!["198.51.100.25".to_string()],
                    mac_address_hash: None,
                },
                TopologyInterfaceNode {
                    name: "eth1".to_string(),
                    index: 3,
                    is_up: true,
                    is_loopback: false,
                    ip_addresses: vec!["192.168.1.100".to_string()],
                    mac_address_hash: None,
                },
            ],
            vec![
                TopologySubnetRecord {
                    network_cidr: "198.51.100.0/24".to_string(),
                    interface_name: "eth0".to_string(),
                    is_ipv6: false,
                    classification: IpClassification::Documentation,
                },
                TopologySubnetRecord {
                    network_cidr: "192.168.1.0/24".to_string(),
                    interface_name: "eth1".to_string(),
                    is_ipv6: false,
                    classification: IpClassification::Private,
                },
            ],
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            vec![],
            vec![],
        );

        let findings = rule.evaluate(&obs);
        assert!(
            findings.is_empty(),
            "Documentation address space (198.51.100.0/24) must NOT be classified as PublicGlobal"
        );
    }

    #[test]
    fn test_net008_simultaneous_public_and_private_physical_interfaces_emits_low_finding() {
        let rule = Net008MultiHomedPublicPrivateRule::new();
        let obs = make_topology_obs(
            vec![
                TopologyInterfaceNode {
                    name: "eth0".to_string(),
                    index: 2,
                    is_up: true,
                    is_loopback: false,
                    ip_addresses: vec!["93.184.216.34".to_string()],
                    mac_address_hash: None,
                },
                TopologyInterfaceNode {
                    name: "eth1".to_string(),
                    index: 3,
                    is_up: true,
                    is_loopback: false,
                    ip_addresses: vec!["192.168.1.100".to_string()],
                    mac_address_hash: None,
                },
            ],
            vec![
                TopologySubnetRecord {
                    network_cidr: "93.184.216.0/24".to_string(),
                    interface_name: "eth0".to_string(),
                    is_ipv6: false,
                    classification: IpClassification::PublicGlobal,
                },
                TopologySubnetRecord {
                    network_cidr: "192.168.1.0/24".to_string(),
                    interface_name: "eth1".to_string(),
                    is_ipv6: false,
                    classification: IpClassification::Private,
                },
            ],
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            vec![],
            vec![],
        );

        let findings = rule.evaluate(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, FindingSeverity::Low);
        assert_eq!(findings[0].target.target_key(), "host:test-host");
        assert_eq!(findings[0].discriminator, "MULTI_HOMED_PUB_PRIV:eth0:eth1");
        assert!(findings[0].description.contains("eth0"));
        assert!(findings[0].description.contains("eth1"));
    }
}
