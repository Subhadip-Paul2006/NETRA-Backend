//! # Rule NET-007: Unroutable or Non-Unicast Address in Neighbor Cache
//!
//! Evaluates whether the Layer-2 / Layer-3 ARP/NDP neighbor cache contains IP addresses
//! belonging to objectively invalid or non-unicast address scopes (Unspecified, Broadcast,
//! Multicast, or Loopback). ARP and NDP are strictly unicast link-layer resolution
//! protocols; presence of non-unicast addresses in the neighbor cache indicates invalid
//! static mappings, table corruption, or malformed stack entries.

use crate::network::IpClassification;
use crate::observation::{Observation, ObservationType, TargetDescriptor};
use crate::rules::network::common::{
    extract_neighbor_payload, format_discriminator, GuardrailDecision, NetworkConfidenceGuardrail,
};
use crate::rules::traits::{FindingRule, RawFinding};
use crate::storage::FindingSeverity;

/// Rule implementation for NET-007: Unroutable or Non-Unicast Address in Neighbor Cache.
pub struct Net007InvalidNeighborEntryRule {
    guardrail: NetworkConfidenceGuardrail,
}

impl Net007InvalidNeighborEntryRule {
    /// Creates a new instance of `Net007InvalidNeighborEntryRule` with standard guardrails.
    pub fn new() -> Self {
        Self {
            guardrail: NetworkConfidenceGuardrail::standard(
                &["scanner.neighbors.v1"],
                FindingSeverity::Low,
            ),
        }
    }
}

impl Default for Net007InvalidNeighborEntryRule {
    fn default() -> Self {
        Self::new()
    }
}

impl FindingRule for Net007InvalidNeighborEntryRule {
    fn rule_id(&self) -> &'static str {
        "NET-007-INVALID-NEIGHBOR-ENTRY"
    }

    fn version(&self) -> u32 {
        1
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Neighbors
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

        // 2. Extract neighbor payload
        let neighbor_payload = match extract_neighbor_payload(obs) {
            Some(p) => p,
            None => return findings,
        };

        // 3. Evaluate each neighbor record
        for n in &neighbor_payload.neighbors {
            let is_invalid = matches!(
                n.ip_classification,
                IpClassification::Unspecified
                    | IpClassification::Broadcast
                    | IpClassification::Multicast
                    | IpClassification::Loopback
            );

            if !is_invalid {
                continue;
            }

            let iface_name = n.interface_name.as_deref().unwrap_or("unknown");
            let classification_str = format!("{:?}", n.ip_classification).to_uppercase();

            let target = TargetDescriptor::NetworkNeighbor {
                ip_address: n.ip_address.clone(),
                interface_name: iface_name.to_string(),
            };

            let discriminator =
                format_discriminator("INVALID_NEIGHBOR", &[&n.ip_address, &classification_str]);

            let title = "Unroutable or Non-Unicast Address in Neighbor Cache".to_string();
            let description = format!(
                "The Layer-2 neighbor cache entry '{}' on interface '{}' has classification {}, which is not a valid unicast neighbor address.",
                n.ip_address, iface_name, classification_str
            );
            let remediation = "Review static ARP/NDP mappings and network device configurations on the local link. Remove invalid or non-unicast static neighbor entries.".to_string();

            let evidence = serde_json::json!({
                "neighbor_ip": n.ip_address,
                "interface_name": iface_name,
                "interface_index": n.interface_index,
                "state": format!("{:?}", n.state).to_uppercase(),
                "classification": classification_str,
                "is_ipv6": n.is_ipv6,
                "reason": "Unroutable or non-unicast address detected in Layer-2 ARP/NDP neighbor cache."
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

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::DeviceId;
    use crate::observation::models::{ConfidenceScore, PrivilegeStatus, SensitivityLevel};
    use crate::observation::payloads::{
        NeighborObservationPayload, NeighborRecord, NeighborState, ObservationPayload,
    };

    fn make_neighbor_observation(
        neighbors: Vec<NeighborRecord>,
        privilege: PrivilegeStatus,
        confidence: ConfidenceScore,
    ) -> Observation {
        Observation::new(
            DeviceId::new(),
            "scanner.neighbors.v1",
            ObservationType::Neighbors,
            TargetDescriptor::Host {
                hostname: "test-host".to_string(),
            },
            10,
            privilege,
            confidence,
            SensitivityLevel::Internal,
            ObservationPayload::Neighbors(NeighborObservationPayload { neighbors }),
        )
        .unwrap()
    }

    #[test]
    fn test_net007_metadata_and_domain() {
        let rule = Net007InvalidNeighborEntryRule::new();
        assert_eq!(rule.rule_id(), "NET-007-INVALID-NEIGHBOR-ENTRY");
        assert_eq!(rule.version(), 1);
        assert_eq!(rule.domain(), ObservationType::Neighbors);
        assert_eq!(rule.default_severity(), FindingSeverity::Low);
    }

    #[test]
    fn test_net007_valid_unicast_neighbors_clean() {
        let rule = Net007InvalidNeighborEntryRule::new();
        let obs = make_neighbor_observation(
            vec![
                NeighborRecord {
                    ip_address: "192.168.1.1".to_string(),
                    mac_address_hash: Some("a1b2c3d4".to_string()),
                    interface_index: 2,
                    interface_name: Some("eth0".to_string()),
                    state: NeighborState::Reachable,
                    is_ipv6: false,
                    ip_classification: IpClassification::Private,
                    is_router: Some(true),
                },
                NeighborRecord {
                    ip_address: "10.0.0.50".to_string(),
                    mac_address_hash: Some("e5f6a1b2".to_string()),
                    interface_index: 2,
                    interface_name: Some("eth0".to_string()),
                    state: NeighborState::Stale,
                    is_ipv6: false,
                    ip_classification: IpClassification::Private,
                    is_router: None,
                },
                NeighborRecord {
                    ip_address: "fe80::1".to_string(),
                    mac_address_hash: Some("c3d4e5f6".to_string()),
                    interface_index: 2,
                    interface_name: Some("eth0".to_string()),
                    state: NeighborState::Reachable,
                    is_ipv6: true,
                    ip_classification: IpClassification::LinkLocal,
                    is_router: Some(true),
                },
                NeighborRecord {
                    ip_address: "93.184.216.34".to_string(),
                    mac_address_hash: Some("d4e5f6a1".to_string()),
                    interface_index: 2,
                    interface_name: Some("eth0".to_string()),
                    state: NeighborState::Stale,
                    is_ipv6: false,
                    ip_classification: IpClassification::PublicGlobal,
                    is_router: None,
                },
            ],
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
        );

        let findings = rule.evaluate(&obs);
        assert!(
            findings.is_empty(),
            "Valid unicast neighbors in Reachable or Stale states must evaluate clean"
        );
    }

    #[test]
    fn test_net007_stale_and_failed_unicast_states_clean() {
        let rule = Net007InvalidNeighborEntryRule::new();
        let obs = make_neighbor_observation(
            vec![
                NeighborRecord {
                    ip_address: "192.168.1.50".to_string(),
                    mac_address_hash: None,
                    interface_index: 2,
                    interface_name: Some("eth0".to_string()),
                    state: NeighborState::Incomplete,
                    is_ipv6: false,
                    ip_classification: IpClassification::Private,
                    is_router: None,
                },
                NeighborRecord {
                    ip_address: "192.168.1.51".to_string(),
                    mac_address_hash: None,
                    interface_index: 2,
                    interface_name: Some("eth0".to_string()),
                    state: NeighborState::Delay,
                    is_ipv6: false,
                    ip_classification: IpClassification::Private,
                    is_router: None,
                },
            ],
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
        );

        let findings = rule.evaluate(&obs);
        assert!(
            findings.is_empty(),
            "Normal state transitions (Incomplete, Delay) on valid IPs must NOT generate findings"
        );
    }

    #[test]
    fn test_net007_invalid_neighbor_addresses_detected() {
        let rule = Net007InvalidNeighborEntryRule::new();
        let obs = make_neighbor_observation(
            vec![
                NeighborRecord {
                    ip_address: "0.0.0.0".to_string(),
                    mac_address_hash: None,
                    interface_index: 2,
                    interface_name: Some("eth0".to_string()),
                    state: NeighborState::Permanent,
                    is_ipv6: false,
                    ip_classification: IpClassification::Unspecified,
                    is_router: None,
                },
                NeighborRecord {
                    ip_address: "255.255.255.255".to_string(),
                    mac_address_hash: None,
                    interface_index: 2,
                    interface_name: Some("eth0".to_string()),
                    state: NeighborState::Permanent,
                    is_ipv6: false,
                    ip_classification: IpClassification::Broadcast,
                    is_router: None,
                },
                NeighborRecord {
                    ip_address: "224.0.0.1".to_string(),
                    mac_address_hash: None,
                    interface_index: 2,
                    interface_name: Some("eth0".to_string()),
                    state: NeighborState::Permanent,
                    is_ipv6: false,
                    ip_classification: IpClassification::Multicast,
                    is_router: None,
                },
                NeighborRecord {
                    ip_address: "127.0.0.1".to_string(),
                    mac_address_hash: None,
                    interface_index: 2,
                    interface_name: Some("eth0".to_string()),
                    state: NeighborState::Permanent,
                    is_ipv6: false,
                    ip_classification: IpClassification::Loopback,
                    is_router: None,
                },
            ],
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
        );

        let findings = rule.evaluate(&obs);
        assert_eq!(findings.len(), 4);
        assert_eq!(findings[0].severity, FindingSeverity::Low);
        assert_eq!(findings[0].target.target_key(), "neighbor:eth0:0.0.0.0");
        assert_eq!(
            findings[0].discriminator,
            "INVALID_NEIGHBOR:0.0.0.0:UNSPECIFIED"
        );
        assert_eq!(
            findings[1].target.target_key(),
            "neighbor:eth0:255.255.255.255"
        );
        assert_eq!(findings[2].target.target_key(), "neighbor:eth0:224.0.0.1");
        assert_eq!(findings[3].target.target_key(), "neighbor:eth0:127.0.0.1");
    }
}
