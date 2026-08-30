//! # Rule NET-006: Loopback Address Space Routed to External Interface
//!
//! Evaluates whether the routing table contains entries directing local host loopback
//! address space (`127.0.0.0/8` or `::1/128`) to an external gateway or non-loopback
//! network interface, contrary to RFC 1122 and RFC 4291 host loopback isolation.

use std::net::IpAddr;

use crate::observation::{Observation, ObservationType, TargetDescriptor};
use crate::rules::network::common::{
    extract_route_payload, format_discriminator, GuardrailDecision, NetworkConfidenceGuardrail,
};
use crate::rules::traits::{FindingRule, RawFinding};
use crate::storage::FindingSeverity;

/// Rule implementation for NET-006: Loopback Address Space Routed to External Interface.
pub struct Net006LoopbackRouteLeakRule {
    guardrail: NetworkConfidenceGuardrail,
}

impl Net006LoopbackRouteLeakRule {
    /// Creates a new instance of `Net006LoopbackRouteLeakRule` with standard guardrails.
    pub fn new() -> Self {
        Self {
            guardrail: NetworkConfidenceGuardrail::standard(
                &["scanner.routes.v1"],
                FindingSeverity::Low,
            ),
        }
    }
}

impl Default for Net006LoopbackRouteLeakRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to determine if a destination CIDR falls within IPv4 or IPv6 loopback space.
fn is_loopback_destination(cidr: &str) -> bool {
    if cidr.starts_with("127.") {
        return true;
    }
    if cidr == "::1/128" || cidr == "::1" {
        return true;
    }
    false
}

/// Helper to determine if an interface name denotes a standard local loopback interface.
fn is_loopback_interface_name(name: Option<&str>) -> bool {
    match name {
        Some(n) => {
            let lower = n.to_lowercase();
            lower == "lo" || lower == "lo0" || lower.starts_with("loopback")
        }
        None => false,
    }
}

/// Helper to determine if a gateway IP represents a local loopback or direct on-link route.
fn is_loopback_gateway(gw: Option<&str>) -> bool {
    match gw {
        Some(ip) => {
            if ip.is_empty() || ip == "0.0.0.0" || ip == "::" {
                // Direct on-link marker, not an external gateway
                return true;
            }
            if let Ok(parsed) = ip.parse::<IpAddr>() {
                parsed.is_loopback()
            } else {
                false
            }
        }
        None => true,
    }
}

impl FindingRule for Net006LoopbackRouteLeakRule {
    fn rule_id(&self) -> &'static str {
        "NET-006-LOOPBACK-ROUTE-LEAK"
    }

    fn version(&self) -> u32 {
        1
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Routes
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

        // 2. Extract Route payload
        let route_payload = match extract_route_payload(obs) {
            Some(p) => p,
            None => return findings,
        };

        // 3. Evaluate each route in the routing table
        for route in &route_payload.routes {
            // Check if destination is loopback space
            if !is_loopback_destination(&route.destination_cidr) {
                continue;
            }

            // Check if route is safely handled by local loopback adapter / gateway
            let is_lo_iface = is_loopback_interface_name(route.interface_name.as_deref());
            let is_lo_gw = is_loopback_gateway(route.gateway_ip.as_deref());

            // A violation occurs if loopback space is routed through an external gateway
            // OR assigned to a confirmed non-loopback network interface with remote/external routing.
            let is_external = !is_lo_gw || (!is_lo_iface && route.interface_name.is_some());

            if !is_external {
                continue;
            }

            let gw_display = route.gateway_ip.as_deref().unwrap_or("none");
            let iface_display = route.interface_name.as_deref().unwrap_or("unknown");
            let target = TargetDescriptor::Route {
                destination: route.destination_cidr.clone(),
                gateway: route.gateway_ip.clone(),
            };

            let discriminator = format_discriminator(
                "LOOPBACK_ROUTE",
                &[
                    &route.destination_cidr,
                    route
                        .gateway_ip
                        .as_deref()
                        .unwrap_or(route.interface_name.as_deref().unwrap_or("external")),
                ],
            );

            let evidence = serde_json::json!({
                "destination_cidr": route.destination_cidr,
                "gateway_ip": route.gateway_ip,
                "interface_index": route.interface_index,
                "interface_name": route.interface_name,
                "metric": route.metric,
                "is_ipv6": route.is_ipv6,
                "route_type": format!("{:?}", route.route_type).to_uppercase(),
                "reason": "Routing table entry directs loopback address space to an external gateway or non-loopback network interface contrary to RFC 1122 loopback isolation requirements"
            });

            findings.push(RawFinding {
                title: "Loopback Address Space Routed to External Interface".to_string(),
                description: format!(
                    "The routing table contains an entry directing local loopback address space '{}' to an external gateway ('{}') or non-loopback interface ('{}'). Standard host networking mandates that loopback address space remain strictly internal to the host (RFC 1122 / RFC 4291).",
                    route.destination_cidr, gw_display, iface_display
                ),
                severity: effective_severity,
                target,
                discriminator,
                remediation_guidance: Some(
                    "Review static route configurations and interface routing metrics. Remove any routing table entries that direct 127.0.0.0/8 or ::1/128 to physical network adapters or external gateways, ensuring loopback prefixes are handled exclusively by the local loopback adapter.".to_string(),
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
        ObservationPayload, RouteObservationPayload, RouteRecord, RouteType,
    };

    fn make_routes_observation(
        routes: Vec<RouteRecord>,
        privilege: PrivilegeStatus,
        confidence: ConfidenceScore,
    ) -> Observation {
        Observation::new(
            DeviceId::new(),
            "scanner.routes.v1",
            ObservationType::Routes,
            TargetDescriptor::Host {
                hostname: "test-host".to_string(),
            },
            10,
            privilege,
            confidence,
            SensitivityLevel::Public,
            ObservationPayload::Routes(RouteObservationPayload {
                routes,
                default_gateways: vec!["192.168.1.1".to_string()],
            }),
        )
        .unwrap()
    }

    #[test]
    fn test_net006_metadata_contracts() {
        let rule = Net006LoopbackRouteLeakRule::new();
        assert_eq!(rule.rule_id(), "NET-006-LOOPBACK-ROUTE-LEAK");
        assert_eq!(rule.version(), 1);
        assert_eq!(rule.domain(), ObservationType::Routes);
        assert_eq!(rule.default_severity(), FindingSeverity::Medium);
    }

    #[test]
    fn test_net006_standard_loopback_routes_clean() {
        let rule = Net006LoopbackRouteLeakRule::new();
        let obs = make_routes_observation(
            vec![
                RouteRecord {
                    destination_cidr: "127.0.0.1/32".to_string(),
                    gateway_ip: Some("127.0.0.1".to_string()),
                    interface_index: 1,
                    interface_name: Some("lo".to_string()),
                    metric: 0,
                    is_ipv6: false,
                    is_default_gateway: false,
                    route_type: RouteType::Local,
                },
                RouteRecord {
                    destination_cidr: "127.0.0.0/8".to_string(),
                    gateway_ip: None,
                    interface_index: 1,
                    interface_name: Some("lo".to_string()),
                    metric: 256,
                    is_ipv6: false,
                    is_default_gateway: false,
                    route_type: RouteType::Direct,
                },
                RouteRecord {
                    destination_cidr: "::1/128".to_string(),
                    gateway_ip: None,
                    interface_index: 1,
                    interface_name: Some("lo".to_string()),
                    metric: 256,
                    is_ipv6: true,
                    is_default_gateway: false,
                    route_type: RouteType::Direct,
                },
                RouteRecord {
                    destination_cidr: "198.51.100.10/32".to_string(),
                    gateway_ip: Some("192.168.1.1".to_string()),
                    interface_index: 2,
                    interface_name: Some("eth0".to_string()),
                    metric: 25,
                    is_ipv6: false,
                    is_default_gateway: false,
                    route_type: RouteType::Remote,
                },
            ],
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
        );

        let findings = rule.evaluate(&obs);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_net006_loopback_routed_externally_detected() {
        let rule = Net006LoopbackRouteLeakRule::new();
        let obs = make_routes_observation(
            vec![
                RouteRecord {
                    destination_cidr: "127.0.0.0/8".to_string(),
                    gateway_ip: Some("192.168.1.1".to_string()),
                    interface_index: 2,
                    interface_name: Some("eth0".to_string()),
                    metric: 25,
                    is_ipv6: false,
                    is_default_gateway: false,
                    route_type: RouteType::Remote,
                },
                RouteRecord {
                    destination_cidr: "::1/128".to_string(),
                    gateway_ip: Some("2001:db8::1".to_string()),
                    interface_index: 2,
                    interface_name: Some("eth0".to_string()),
                    metric: 25,
                    is_ipv6: true,
                    is_default_gateway: false,
                    route_type: RouteType::Remote,
                },
            ],
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
        );

        let findings = rule.evaluate(&obs);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, FindingSeverity::Medium);
        assert_eq!(
            findings[0].target.target_key(),
            "route:127.0.0.0/8:192.168.1.1"
        );
        assert_eq!(
            findings[0].discriminator,
            "LOOPBACK_ROUTE:127.0.0.0/8:192.168.1.1"
        );
        assert_eq!(findings[1].severity, FindingSeverity::Medium);
        assert_eq!(findings[1].target.target_key(), "route:::1/128:2001:db8::1");
    }
}
