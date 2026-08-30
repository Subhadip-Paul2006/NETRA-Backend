//! # Rule NET-005: Invalid or Unroutable DNS Nameserver Configuration
//!
//! Evaluates whether configured DNS nameserver addresses belong to objectively
//! unroutable, non-unicast, or invalid address scopes (Unspecified, Broadcast,
//! Multicast, or Documentation).

use crate::network::IpClassification;
use crate::observation::{Observation, ObservationType, TargetDescriptor};
use crate::rules::network::common::{
    extract_dns_payload, format_discriminator, GuardrailDecision, NetworkConfidenceGuardrail,
};
use crate::rules::traits::{FindingRule, RawFinding};
use crate::storage::FindingSeverity;

/// Rule implementation for NET-005: Invalid or Unroutable DNS Nameserver Configuration.
pub struct Net005InvalidDnsResolverRule {
    guardrail: NetworkConfidenceGuardrail,
}

impl Net005InvalidDnsResolverRule {
    /// Creates a new instance of `Net005InvalidDnsResolverRule` with standard guardrails.
    pub fn new() -> Self {
        Self {
            guardrail: NetworkConfidenceGuardrail::standard(
                &["scanner.dns.v1"],
                FindingSeverity::Low,
            ),
        }
    }
}

impl Default for Net005InvalidDnsResolverRule {
    fn default() -> Self {
        Self::new()
    }
}

impl FindingRule for Net005InvalidDnsResolverRule {
    fn rule_id(&self) -> &'static str {
        "NET-005-INVALID-DNS-RESOLVER"
    }

    fn version(&self) -> u32 {
        1
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Dns
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

        // 2. Extract DNS payload
        let dns_payload = match extract_dns_payload(obs) {
            Some(p) => p,
            None => return findings,
        };

        // 3. Iterate through configured DNS servers
        for server in &dns_payload.dns_servers {
            let is_invalid = matches!(
                server.classification,
                IpClassification::Unspecified
                    | IpClassification::Broadcast
                    | IpClassification::Multicast
                    | IpClassification::Documentation
            );

            if !is_invalid {
                continue;
            }

            let classification_str = format!("{:?}", server.classification).to_uppercase();
            let target = TargetDescriptor::DnsServer {
                server_address: server.server_address.clone(),
            };
            let discriminator = format_discriminator(
                "INVALID_DNS",
                &[&server.server_address, &classification_str],
            );

            let evidence = serde_json::json!({
                "server_address": server.server_address,
                "interface_name": server.interface_name,
                "is_ipv6": server.is_ipv6,
                "classification": classification_str,
                "reason": "Nameserver IP address belongs to unroutable or non-unicast address classification"
            });

            findings.push(RawFinding {
                title: "Invalid or Unroutable DNS Nameserver Configuration".to_string(),
                description: format!(
                    "Configured DNS nameserver '{}' belongs to an unroutable or non-unicast address scope ({}).",
                    server.server_address, classification_str
                ),
                severity: effective_severity,
                target,
                discriminator,
                remediation_guidance: Some(
                    "Review host DNS settings, /etc/resolv.conf, or DHCP client configuration. Replace invalid nameserver IP addresses with valid unicast DNS resolver addresses.".to_string(),
                ),
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
        DnsObservationPayload, DnsServerRecord, ObservationPayload,
    };

    fn make_dns_observation(
        servers: Vec<DnsServerRecord>,
        privilege: PrivilegeStatus,
        confidence: ConfidenceScore,
    ) -> Observation {
        Observation::new(
            DeviceId::new(),
            "scanner.dns.v1",
            ObservationType::Dns,
            TargetDescriptor::Host {
                hostname: "test-host".to_string(),
            },
            10,
            privilege,
            confidence,
            SensitivityLevel::Public,
            ObservationPayload::Dns(DnsObservationPayload {
                dns_servers: servers,
                search_domains: vec!["local".to_string()],
                is_dynamic_dns_enabled: None,
            }),
        )
        .unwrap()
    }

    #[test]
    fn test_net005_metadata_contracts() {
        let rule = Net005InvalidDnsResolverRule::new();
        assert_eq!(rule.rule_id(), "NET-005-INVALID-DNS-RESOLVER");
        assert_eq!(rule.version(), 1);
        assert_eq!(rule.domain(), ObservationType::Dns);
        assert_eq!(rule.default_severity(), FindingSeverity::Low);
    }

    #[test]
    fn test_net005_valid_resolvers_clean() {
        let rule = Net005InvalidDnsResolverRule::new();
        let obs = make_dns_observation(
            vec![
                DnsServerRecord {
                    server_address: "8.8.8.8".to_string(),
                    interface_name: Some("eth0".to_string()),
                    is_ipv6: false,
                    classification: IpClassification::PublicGlobal,
                },
                DnsServerRecord {
                    server_address: "192.168.1.1".to_string(),
                    interface_name: Some("eth0".to_string()),
                    is_ipv6: false,
                    classification: IpClassification::Private,
                },
                DnsServerRecord {
                    server_address: "127.0.0.53".to_string(),
                    interface_name: None,
                    is_ipv6: false,
                    classification: IpClassification::Loopback,
                },
                DnsServerRecord {
                    server_address: "fe80::1".to_string(),
                    interface_name: Some("eth0".to_string()),
                    is_ipv6: true,
                    classification: IpClassification::LinkLocal,
                },
            ],
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
        );

        let findings = rule.evaluate(&obs);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_net005_unspecified_and_broadcast_resolvers_detected() {
        let rule = Net005InvalidDnsResolverRule::new();
        let obs = make_dns_observation(
            vec![
                DnsServerRecord {
                    server_address: "0.0.0.0".to_string(),
                    interface_name: Some("eth0".to_string()),
                    is_ipv6: false,
                    classification: IpClassification::Unspecified,
                },
                DnsServerRecord {
                    server_address: "255.255.255.255".to_string(),
                    interface_name: Some("eth0".to_string()),
                    is_ipv6: false,
                    classification: IpClassification::Broadcast,
                },
                DnsServerRecord {
                    server_address: "224.0.0.251".to_string(),
                    interface_name: None,
                    is_ipv6: false,
                    classification: IpClassification::Multicast,
                },
                DnsServerRecord {
                    server_address: "192.0.2.1".to_string(),
                    interface_name: None,
                    is_ipv6: false,
                    classification: IpClassification::Documentation,
                },
            ],
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
        );

        let findings = rule.evaluate(&obs);
        assert_eq!(findings.len(), 4);
        assert_eq!(findings[0].severity, FindingSeverity::Low);
        assert_eq!(findings[0].target.target_key(), "dns_server:0.0.0.0");
        assert_eq!(findings[0].discriminator, "INVALID_DNS:0.0.0.0:UNSPECIFIED");
        assert_eq!(
            findings[1].target.target_key(),
            "dns_server:255.255.255.255"
        );
        assert_eq!(findings[2].target.target_key(), "dns_server:224.0.0.251");
        assert_eq!(findings[3].target.target_key(), "dns_server:192.0.2.1");
    }
}
