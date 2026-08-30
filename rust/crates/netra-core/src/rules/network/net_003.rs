//! # Rule NET-003: Default Gateway Address Outside Local Interface Subnet
//!
//! Evaluates whether an active default gateway (`0.0.0.0/0` or `::/0`) has an egress IP
//! address that does not belong to any locally assigned subnet CIDR on the egress interface.

use std::net::IpAddr;

use crate::network::topology::ip_in_cidr;
use crate::observation::{Observation, ObservationType, TargetDescriptor};
use crate::rules::network::common::{
    extract_topology_payload, format_discriminator, GuardrailDecision, NetworkConfidenceGuardrail,
};
use crate::rules::traits::{FindingRule, RawFinding};
use crate::storage::FindingSeverity;

/// Rule implementation for NET-003: Default Gateway Address Outside Local Interface Subnet.
pub struct Net003GatewayOffSubnetRule {
    guardrail: NetworkConfidenceGuardrail,
}

impl Net003GatewayOffSubnetRule {
    /// Creates a new instance of `Net003GatewayOffSubnetRule` with standard guardrails.
    pub fn new() -> Self {
        Self {
            guardrail: NetworkConfidenceGuardrail::standard(
                &["scanner.routes.v1", "scanner.interfaces.v1"],
                FindingSeverity::Low,
            ),
        }
    }
}

impl Default for Net003GatewayOffSubnetRule {
    fn default() -> Self {
        Self::new()
    }
}

impl FindingRule for Net003GatewayOffSubnetRule {
    fn rule_id(&self) -> &'static str {
        "NET-003-GATEWAY-OFF-SUBNET"
    }

    fn version(&self) -> u32 {
        1
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Topology
    }

    fn default_severity(&self) -> FindingSeverity {
        FindingSeverity::Medium
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

        // 3. Iterate through active default gateways
        for gw in &topo.snapshot.default_gateways {
            // Filter 1: IPv6 Link-Local default routers (RFC 4861 / RFC 4862)
            if gw.is_ipv6 {
                if let Ok(IpAddr::V6(v6)) = gw.gateway_ip.parse::<IpAddr>() {
                    // Check if fe80::/10 (link-local unicast)
                    if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                        // Standard IPv6 on-link router behavior; do not flag.
                        continue;
                    }
                }
            }

            // Locate interface node if present
            let iface = topo.snapshot.interfaces.iter().find(|i| {
                gw.interface_name.as_deref() == Some(&i.name) || gw.interface_index == i.index
            });

            // Filter 2: Loopback interfaces
            if let Some(iface) = iface {
                if iface.is_loopback {
                    continue;
                }
            }

            // Find all subnets associated with this interface
            let iface_subnets: Vec<&crate::network::TopologySubnetRecord> = topo
                .snapshot
                .subnets
                .iter()
                .filter(|s| {
                    gw.interface_name.as_deref() == Some(&s.interface_name)
                        || iface.map(|i| i.name == s.interface_name).unwrap_or(false)
                })
                .collect();

            // Filter 3: Unnumbered L3 / point-to-point tunnel interface
            // If the interface is observed but has zero assigned broadcast subnets
            if iface.is_some() && iface_subnets.is_empty() {
                continue;
            }

            // Check if gateway IP belongs to any assigned interface subnet
            let mut is_on_subnet = false;
            for subnet in &iface_subnets {
                if ip_in_cidr(&gw.gateway_ip, &subnet.network_cidr) {
                    is_on_subnet = true;
                    break;
                }
            }

            if is_on_subnet {
                continue;
            }

            // Violation detected: gateway is outside all locally observed subnets
            let iface_display = gw.interface_name.as_deref().unwrap_or("unknown");
            let target = TargetDescriptor::Route {
                destination: if gw.is_ipv6 {
                    "::/0".to_string()
                } else {
                    "0.0.0.0/0".to_string()
                },
                gateway: Some(gw.gateway_ip.clone()),
            };

            let discriminator =
                format_discriminator("OFF_SUBNET_GW", &[&gw.gateway_ip, iface_display]);

            let subnet_cidrs: Vec<String> = iface_subnets
                .iter()
                .map(|s| s.network_cidr.clone())
                .collect();

            findings.push(RawFinding {
                title: "Default Gateway Address Outside Local Interface Subnet".to_string(),
                description: format!(
                    "The configured default gateway IP '{}' does not belong to any locally assigned subnet on interface '{}'.",
                    gw.gateway_ip, iface_display
                ),
                severity: effective_severity,
                target,
                discriminator,
                remediation_guidance: Some(
                    "Review static route configurations or DHCP option 3 settings for the affected interface. Ensure the default gateway belongs to the local subnet CIDR unless operating over a dedicated point-to-point or tunnel link.".to_string(),
                ),
                raw_evidence: serde_json::json!({
                    "gateway_ip": gw.gateway_ip,
                    "interface_name": gw.interface_name,
                    "interface_index": gw.interface_index,
                    "metric": gw.metric,
                    "is_ipv6": gw.is_ipv6,
                    "observed_interface_subnets": subnet_cidrs,
                    "reason": format!(
                        "Gateway IP '{}' is not contained within any observed local interface subnet CIDR.",
                        gw.gateway_ip
                    )
                }),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::DeviceId;
    use crate::network::{
        IpClassification, NetworkTopologySnapshot, TopologyGatewayNode, TopologyInterfaceNode,
        TopologyObservationPayload, TopologySubnetRecord,
    };
    use crate::observation::{
        ConfidenceScore, ObservationPayload, PrivilegeStatus, SensitivityLevel,
    };
    use chrono::Utc;

    fn make_test_topo_obs(
        gateways: Vec<TopologyGatewayNode>,
        subnets: Vec<TopologySubnetRecord>,
        interfaces: Vec<TopologyInterfaceNode>,
        confidence: ConfidenceScore,
        missing: Vec<String>,
        partial: Vec<String>,
    ) -> Observation {
        Observation::new(
            DeviceId::new(),
            "scanner.topology.v1",
            ObservationType::Topology,
            TargetDescriptor::Host {
                hostname: "test-host".to_string(),
            },
            10,
            PrivilegeStatus::Available,
            confidence,
            SensitivityLevel::Public,
            ObservationPayload::Topology(TopologyObservationPayload {
                snapshot: NetworkTopologySnapshot {
                    schema_version: 1,
                    device_id: DeviceId::new(),
                    generated_at: Utc::now(),
                    interfaces,
                    default_gateways: gateways,
                    dns_resolvers: vec![],
                    neighbors: vec![],
                    subnets,
                    is_multi_homed: false,
                    confidence,
                    provenance_sources: vec![
                        "scanner.routes.v1".to_string(),
                        "scanner.interfaces.v1".to_string(),
                    ],
                },
                edges: vec![],
                missing_sources: missing,
                partial_sources: partial,
            }),
        )
        .unwrap()
    }

    #[test]
    fn test_net003_metadata_contracts() {
        let rule = Net003GatewayOffSubnetRule::new();
        assert_eq!(rule.rule_id(), "NET-003-GATEWAY-OFF-SUBNET");
        assert_eq!(rule.version(), 1);
        assert_eq!(rule.domain(), ObservationType::Topology);
        assert_eq!(rule.default_severity(), FindingSeverity::Medium);
    }

    #[test]
    fn test_net003_on_subnet_ipv4_gateway_clean() {
        let rule = Net003GatewayOffSubnetRule::new();
        let obs = make_test_topo_obs(
            vec![TopologyGatewayNode {
                gateway_ip: "192.168.1.1".to_string(),
                interface_index: 1,
                interface_name: Some("eth0".to_string()),
                metric: 10,
                is_ipv6: false,
            }],
            vec![TopologySubnetRecord {
                network_cidr: "192.168.1.0/24".to_string(),
                interface_name: "eth0".to_string(),
                is_ipv6: false,
                classification: IpClassification::Private,
            }],
            vec![TopologyInterfaceNode {
                name: "eth0".to_string(),
                index: 1,
                is_up: true,
                is_loopback: false,
                ip_addresses: vec!["192.168.1.50".to_string()],
                mac_address_hash: None,
            }],
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            vec![],
            vec![],
        );

        let findings = rule.evaluate(&obs);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_net003_off_subnet_ipv4_gateway_detected() {
        let rule = Net003GatewayOffSubnetRule::new();
        let obs = make_test_topo_obs(
            vec![TopologyGatewayNode {
                gateway_ip: "10.0.0.1".to_string(),
                interface_index: 1,
                interface_name: Some("eth0".to_string()),
                metric: 10,
                is_ipv6: false,
            }],
            vec![TopologySubnetRecord {
                network_cidr: "192.168.1.0/24".to_string(),
                interface_name: "eth0".to_string(),
                is_ipv6: false,
                classification: IpClassification::Private,
            }],
            vec![TopologyInterfaceNode {
                name: "eth0".to_string(),
                index: 1,
                is_up: true,
                is_loopback: false,
                ip_addresses: vec!["192.168.1.50".to_string()],
                mac_address_hash: None,
            }],
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            vec![],
            vec![],
        );

        let findings = rule.evaluate(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, FindingSeverity::Medium);
        assert_eq!(findings[0].discriminator, "OFF_SUBNET_GW:10.0.0.1:eth0");
    }
}
