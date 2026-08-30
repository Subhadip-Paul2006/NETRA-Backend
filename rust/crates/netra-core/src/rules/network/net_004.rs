//! # Rule NET-004: Equal-Metric Competing Default Gateways Detected
//!
//! Evaluates whether multiple active default gateway routes share the exact same metric
//! priority within the same address family (IPv4 or IPv6), leading to egress routing
//! ambiguity or traffic splitting across network adapters.

use std::collections::BTreeMap;

use crate::network::TopologyGatewayNode;
use crate::observation::{Observation, ObservationType, TargetDescriptor};
use crate::rules::network::common::{
    extract_topology_payload, format_discriminator, GuardrailDecision, NetworkConfidenceGuardrail,
};
use crate::rules::traits::{FindingRule, RawFinding};
use crate::storage::FindingSeverity;

/// Rule implementation for NET-004: Equal-Metric Competing Default Gateways Detected.
pub struct Net004CompetingGatewaysRule {
    guardrail: NetworkConfidenceGuardrail,
}

impl Net004CompetingGatewaysRule {
    /// Creates a new instance of `Net004CompetingGatewaysRule` with standard guardrails.
    pub fn new() -> Self {
        Self {
            guardrail: NetworkConfidenceGuardrail::standard(
                &["scanner.routes.v1"],
                FindingSeverity::Low,
            ),
        }
    }
}

impl Default for Net004CompetingGatewaysRule {
    fn default() -> Self {
        Self::new()
    }
}

impl FindingRule for Net004CompetingGatewaysRule {
    fn rule_id(&self) -> &'static str {
        "NET-004-COMPETING-DEFAULT-GATEWAYS"
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

        // 3. Partition default gateways by address family (independent evaluation)
        let mut ipv4_gateways: Vec<&TopologyGatewayNode> = Vec::new();
        let mut ipv6_gateways: Vec<&TopologyGatewayNode> = Vec::new();

        for gw in &topo.snapshot.default_gateways {
            if gw.is_ipv6 {
                ipv6_gateways.push(gw);
            } else {
                ipv4_gateways.push(gw);
            }
        }

        let family_partitions = [("IPv4", ipv4_gateways), ("IPv6", ipv6_gateways)];

        for (family_name, gateways) in family_partitions {
            if gateways.len() <= 1 {
                continue;
            }

            // Group gateways by exact metric
            let mut metric_groups: BTreeMap<u32, Vec<&TopologyGatewayNode>> = BTreeMap::new();
            for gw in gateways {
                metric_groups.entry(gw.metric).or_default().push(gw);
            }

            for (metric, group) in metric_groups {
                let mut unique_ips: Vec<&str> =
                    group.iter().map(|g| g.gateway_ip.as_str()).collect();
                unique_ips.sort_unstable();
                unique_ips.dedup();

                // Only flag if there are multiple DISTINCT gateway IPs with the exact same metric
                if unique_ips.len() > 1 {
                    let sorted_ips_str = unique_ips.join("_");

                    let target = TargetDescriptor::Host {
                        hostname: match &obs.target {
                            TargetDescriptor::Host { hostname } => hostname.clone(),
                            _ => "host".to_string(),
                        },
                    };

                    let discriminator = format_discriminator(
                        "EQUAL_METRIC_GW",
                        &[family_name, &metric.to_string(), &sorted_ips_str],
                    );

                    let competing_info: Vec<serde_json::Value> = group
                        .iter()
                        .map(|gw| {
                            serde_json::json!({
                                "gateway_ip": gw.gateway_ip,
                                "interface_name": gw.interface_name,
                                "interface_index": gw.interface_index,
                                "metric": gw.metric,
                            })
                        })
                        .collect();

                    findings.push(RawFinding {
                        title: "Equal-Metric Competing Default Gateways Detected".to_string(),
                        description: format!(
                            "Multiple active {} default routes share the same metric ({}) across gateways: {}.",
                            family_name,
                            metric,
                            unique_ips.join(", ")
                        ),
                        severity: effective_severity,
                        target,
                        discriminator,
                        remediation_guidance: Some(
                            "Review interface route metrics in OS network adapter settings or routing daemons. Assign an explicitly lower metric to the primary network adapter to establish an unambiguous default egress path.".to_string(),
                        ),
                        raw_evidence: serde_json::json!({
                            "address_family": family_name,
                            "shared_metric": metric,
                            "competing_gateways": competing_info,
                            "reason": format!(
                                "Multiple active {} default routes share identical metric {} across distinct gateway addresses.",
                                family_name, metric
                            )
                        }),
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::DeviceId;
    use crate::network::{NetworkTopologySnapshot, TopologyObservationPayload};
    use crate::observation::{
        ConfidenceScore, ObservationPayload, PrivilegeStatus, SensitivityLevel,
    };
    use chrono::Utc;

    fn make_test_topo_obs(
        gateways: Vec<TopologyGatewayNode>,
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
                    interfaces: vec![],
                    default_gateways: gateways,
                    dns_resolvers: vec![],
                    neighbors: vec![],
                    subnets: vec![],
                    is_multi_homed: false,
                    confidence,
                    provenance_sources: vec!["scanner.routes.v1".to_string()],
                },
                edges: vec![],
                missing_sources: missing,
                partial_sources: partial,
            }),
        )
        .unwrap()
    }

    #[test]
    fn test_net004_metadata_contracts() {
        let rule = Net004CompetingGatewaysRule::new();
        assert_eq!(rule.rule_id(), "NET-004-COMPETING-DEFAULT-GATEWAYS");
        assert_eq!(rule.version(), 1);
        assert_eq!(rule.domain(), ObservationType::Topology);
        assert_eq!(rule.default_severity(), FindingSeverity::Low);
    }

    #[test]
    fn test_net004_single_gateway_clean() {
        let rule = Net004CompetingGatewaysRule::new();
        let obs = make_test_topo_obs(
            vec![TopologyGatewayNode {
                gateway_ip: "192.168.1.1".to_string(),
                interface_index: 1,
                interface_name: Some("eth0".to_string()),
                metric: 10,
                is_ipv6: false,
            }],
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            vec![],
            vec![],
        );

        let findings = rule.evaluate(&obs);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_net004_distinct_metrics_failover_clean() {
        let rule = Net004CompetingGatewaysRule::new();
        let obs = make_test_topo_obs(
            vec![
                TopologyGatewayNode {
                    gateway_ip: "192.168.1.1".to_string(),
                    interface_index: 1,
                    interface_name: Some("eth0".to_string()),
                    metric: 10,
                    is_ipv6: false,
                },
                TopologyGatewayNode {
                    gateway_ip: "10.0.0.1".to_string(),
                    interface_index: 2,
                    interface_name: Some("wlan0".to_string()),
                    metric: 25,
                    is_ipv6: false,
                },
            ],
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            vec![],
            vec![],
        );

        let findings = rule.evaluate(&obs);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_net004_equal_metrics_competing_detected() {
        let rule = Net004CompetingGatewaysRule::new();
        let obs = make_test_topo_obs(
            vec![
                TopologyGatewayNode {
                    gateway_ip: "192.168.1.1".to_string(),
                    interface_index: 1,
                    interface_name: Some("eth0".to_string()),
                    metric: 25,
                    is_ipv6: false,
                },
                TopologyGatewayNode {
                    gateway_ip: "10.0.0.1".to_string(),
                    interface_index: 2,
                    interface_name: Some("wlan0".to_string()),
                    metric: 25,
                    is_ipv6: false,
                },
            ],
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            vec![],
            vec![],
        );

        let findings = rule.evaluate(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, FindingSeverity::Low);
        assert_eq!(
            findings[0].discriminator,
            "EQUAL_METRIC_GW:IPv4:25:10.0.0.1_192.168.1.1"
        );
    }
}
