//! # Network Posture Rule Utilities & Confidence Guardrails
//!
//! Common, platform-neutral helper utilities, evidence sanitization, and deterministic
//! confidence guardrail policies for network security posture finding rules (Phase 8.7).

use crate::network::topology::TopologyObservationPayload;
use crate::observation::payloads::{
    DnsObservationPayload, InterfaceObservationPayload, NeighborObservationPayload,
    ObservationPayload, RouteObservationPayload,
};
use crate::observation::{ConfidenceScore, Observation, ObservationType, PrivilegeStatus};
use crate::storage::FindingSeverity;

/// Deterministic action to take when an observation does not meet confidence or privilege requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidenceAction {
    /// Allow the finding to be emitted at its configured default severity.
    Allow,
    /// Suppress the finding entirely (do not emit).
    Suppress,
    /// Downgrade the finding severity to a specific lower level.
    Downgrade(FindingSeverity),
}

/// Decision returned by [`NetworkConfidenceGuardrail::evaluate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardrailDecision {
    /// Proceed with evaluating and emitting the finding using the specified effective severity.
    Proceed(FindingSeverity),
    /// Suppress the finding due to insufficient observation confidence or missing provenance.
    Suppress,
}

/// Deterministic guardrail policy controlling rule evaluation based on observation confidence and source provenance.
#[derive(Debug, Clone)]
pub struct NetworkConfidenceGuardrail {
    /// Minimum numerical confidence score required (e.g. `0.7` for `UNPRIVILEGED_PARTIAL`, `0.9` for `SYSTEM_TABLE`).
    pub min_confidence: ConfidenceScore,
    /// Minimum required privilege status.
    pub min_privilege: PrivilegeStatus,
    /// Specific scanner IDs required for this rule to evaluate reliably (e.g. `["scanner.routes.v1"]`).
    pub required_sources: &'static [&'static str],
    /// Action when observation confidence is strictly below `min_confidence`.
    pub on_low_confidence: ConfidenceAction,
    /// Action when a required scanner source is missing from the observation/topology.
    pub on_missing_source: ConfidenceAction,
    /// Action when a required scanner source is present but only in `Partial` or `Unsupported` privilege status.
    pub on_partial_source: ConfidenceAction,
}

impl NetworkConfidenceGuardrail {
    /// Creates a strict guardrail policy requiring `KERNEL_AUTHORITATIVE` (1.0) and suppressing on any degradation.
    pub const fn strict(required_sources: &'static [&'static str]) -> Self {
        Self {
            min_confidence: ConfidenceScore::KERNEL_AUTHORITATIVE,
            min_privilege: PrivilegeStatus::Available,
            required_sources,
            on_low_confidence: ConfidenceAction::Suppress,
            on_missing_source: ConfidenceAction::Suppress,
            on_partial_source: ConfidenceAction::Suppress,
        }
    }

    /// Creates a standard guardrail policy requiring `UNPRIVILEGED_PARTIAL` (0.7) and downgrading severity on lower confidence.
    pub const fn standard(
        required_sources: &'static [&'static str],
        downgrade_severity: FindingSeverity,
    ) -> Self {
        Self {
            min_confidence: ConfidenceScore::UNPRIVILEGED_PARTIAL,
            min_privilege: PrivilegeStatus::Available,
            required_sources,
            on_low_confidence: ConfidenceAction::Downgrade(downgrade_severity),
            on_missing_source: ConfidenceAction::Suppress,
            on_partial_source: ConfidenceAction::Downgrade(downgrade_severity),
        }
    }

    /// Creates a permissive guardrail policy allowing heuristic evaluation.
    pub const fn permissive(required_sources: &'static [&'static str]) -> Self {
        Self {
            min_confidence: ConfidenceScore::HEURISTIC,
            min_privilege: PrivilegeStatus::Partial,
            required_sources,
            on_low_confidence: ConfidenceAction::Allow,
            on_missing_source: ConfidenceAction::Suppress,
            on_partial_source: ConfidenceAction::Allow,
        }
    }

    /// Evaluates the observation against this guardrail policy.
    pub fn evaluate(
        &self,
        obs: &Observation,
        default_severity: FindingSeverity,
    ) -> GuardrailDecision {
        // 1. Check if observation is Topology and has missing or partial required sources
        if obs.observation_type == ObservationType::Topology {
            if let ObservationPayload::Topology(ref topo) = obs.payload {
                for &req in self.required_sources {
                    if topo.missing_sources.iter().any(|s| s == req) {
                        return match self.on_missing_source {
                            ConfidenceAction::Allow => GuardrailDecision::Proceed(default_severity),
                            ConfidenceAction::Suppress => GuardrailDecision::Suppress,
                            ConfidenceAction::Downgrade(sev) => GuardrailDecision::Proceed(sev),
                        };
                    }
                    if topo.partial_sources.iter().any(|s| s == req) {
                        return match self.on_partial_source {
                            ConfidenceAction::Allow => GuardrailDecision::Proceed(default_severity),
                            ConfidenceAction::Suppress => GuardrailDecision::Suppress,
                            ConfidenceAction::Downgrade(sev) => GuardrailDecision::Proceed(sev),
                        };
                    }
                }
            }
        }

        // 2. Check privilege status
        match obs.privilege_level {
            PrivilegeStatus::PermissionDenied | PrivilegeStatus::Error => {
                return GuardrailDecision::Suppress;
            }
            PrivilegeStatus::Unsupported => match self.on_missing_source {
                ConfidenceAction::Allow => {}
                ConfidenceAction::Suppress => return GuardrailDecision::Suppress,
                ConfidenceAction::Downgrade(sev) => return GuardrailDecision::Proceed(sev),
            },
            PrivilegeStatus::Partial => {
                if self.min_privilege == PrivilegeStatus::Available {
                    match self.on_partial_source {
                        ConfidenceAction::Allow => {}
                        ConfidenceAction::Suppress => return GuardrailDecision::Suppress,
                        ConfidenceAction::Downgrade(sev) => return GuardrailDecision::Proceed(sev),
                    }
                }
            }
            PrivilegeStatus::Available => {}
        }

        // 3. Check numerical confidence score threshold
        if obs.confidence.value() < self.min_confidence.value() {
            match self.on_low_confidence {
                ConfidenceAction::Allow => GuardrailDecision::Proceed(default_severity),
                ConfidenceAction::Suppress => GuardrailDecision::Suppress,
                ConfidenceAction::Downgrade(sev) => GuardrailDecision::Proceed(sev),
            }
        } else {
            GuardrailDecision::Proceed(default_severity)
        }
    }
}

/// Helper function to extract a [`TopologyObservationPayload`] reference from an observation.
pub fn extract_topology_payload(obs: &Observation) -> Option<&TopologyObservationPayload> {
    match &obs.payload {
        ObservationPayload::Topology(payload) => Some(payload),
        _ => None,
    }
}

/// Helper function to extract an [`InterfaceObservationPayload`] reference from an observation.
pub fn extract_interface_payload(obs: &Observation) -> Option<&InterfaceObservationPayload> {
    match &obs.payload {
        ObservationPayload::Interfaces(payload) => Some(payload),
        _ => None,
    }
}

/// Helper function to extract a [`RouteObservationPayload`] reference from an observation.
pub fn extract_route_payload(obs: &Observation) -> Option<&RouteObservationPayload> {
    match &obs.payload {
        ObservationPayload::Routes(payload) => Some(payload),
        _ => None,
    }
}

/// Helper function to extract a [`DnsObservationPayload`] reference from an observation.
pub fn extract_dns_payload(obs: &Observation) -> Option<&DnsObservationPayload> {
    match &obs.payload {
        ObservationPayload::Dns(payload) => Some(payload),
        _ => None,
    }
}

/// Helper function to extract a [`NeighborObservationPayload`] reference from an observation.
pub fn extract_neighbor_payload(obs: &Observation) -> Option<&NeighborObservationPayload> {
    match &obs.payload {
        ObservationPayload::Neighbors(payload) => Some(payload),
        _ => None,
    }
}

/// Formats a deterministic discriminator string from a rule prefix and ordered key parts.
pub fn format_discriminator(prefix: &str, parts: &[&str]) -> String {
    if parts.is_empty() {
        prefix.to_string()
    } else {
        format!("{}:{}", prefix, parts.join(":"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::DeviceId;
    use crate::network::topology::NetworkTopologySnapshot;
    use crate::observation::target::TargetDescriptor;
    use crate::observation::SensitivityLevel;

    fn make_test_obs(
        obs_type: ObservationType,
        priv_status: PrivilegeStatus,
        confidence: ConfidenceScore,
        payload: ObservationPayload,
    ) -> Observation {
        Observation::new(
            DeviceId::new(),
            "scanner.test.v1",
            obs_type,
            TargetDescriptor::Host {
                hostname: "test-host".to_string(),
            },
            10,
            priv_status,
            confidence,
            SensitivityLevel::Public,
            payload,
        )
        .unwrap()
    }

    #[test]
    fn test_guardrail_strict_policy() {
        let guardrail = NetworkConfidenceGuardrail::strict(&["scanner.routes.v1"]);

        // High confidence + Available -> Proceed
        let obs_good = make_test_obs(
            ObservationType::Routes,
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            ObservationPayload::Routes(RouteObservationPayload {
                routes: vec![],
                default_gateways: vec![],
            }),
        );
        assert_eq!(
            guardrail.evaluate(&obs_good, FindingSeverity::High),
            GuardrailDecision::Proceed(FindingSeverity::High)
        );

        // Lower confidence -> Suppress
        let obs_low = make_test_obs(
            ObservationType::Routes,
            PrivilegeStatus::Available,
            ConfidenceScore::UNPRIVILEGED_PARTIAL,
            ObservationPayload::Routes(RouteObservationPayload {
                routes: vec![],
                default_gateways: vec![],
            }),
        );
        assert_eq!(
            guardrail.evaluate(&obs_low, FindingSeverity::High),
            GuardrailDecision::Suppress
        );
    }

    #[test]
    fn test_guardrail_standard_policy_downgrade() {
        let guardrail =
            NetworkConfidenceGuardrail::standard(&["scanner.dns.v1"], FindingSeverity::Medium);

        // Score below 0.7 -> Downgrade to Medium
        let obs_heuristic = make_test_obs(
            ObservationType::Dns,
            PrivilegeStatus::Available,
            ConfidenceScore::HEURISTIC,
            ObservationPayload::Dns(DnsObservationPayload {
                dns_servers: vec![],
                search_domains: vec![],
                is_dynamic_dns_enabled: None,
            }),
        );
        assert_eq!(
            guardrail.evaluate(&obs_heuristic, FindingSeverity::High),
            GuardrailDecision::Proceed(FindingSeverity::Medium)
        );
    }

    #[test]
    fn test_guardrail_topology_missing_source_check() {
        let guardrail = NetworkConfidenceGuardrail::strict(&["scanner.neighbors.v1"]);

        let topo_payload = TopologyObservationPayload {
            snapshot: NetworkTopologySnapshot {
                schema_version: 1,
                device_id: DeviceId::new(),
                generated_at: chrono::Utc::now(),
                interfaces: vec![],
                default_gateways: vec![],
                dns_resolvers: vec![],
                neighbors: vec![],
                subnets: vec![],
                is_multi_homed: false,
                confidence: ConfidenceScore::SYSTEM_TABLE,
                provenance_sources: vec!["scanner.interfaces.v1".to_string()],
            },
            edges: vec![],
            missing_sources: vec!["scanner.neighbors.v1".to_string()],
            partial_sources: vec![],
        };

        let obs_topo = make_test_obs(
            ObservationType::Topology,
            PrivilegeStatus::Available,
            ConfidenceScore::SYSTEM_TABLE,
            ObservationPayload::Topology(topo_payload),
        );

        assert_eq!(
            guardrail.evaluate(&obs_topo, FindingSeverity::High),
            GuardrailDecision::Suppress
        );
    }

    #[test]
    fn test_format_discriminator() {
        assert_eq!(
            format_discriminator("ROGUE_GW", &["192.168.1.1", "eth0"]),
            "ROGUE_GW:192.168.1.1:eth0"
        );
        assert_eq!(format_discriminator("EMPTY", &[]), "EMPTY");
    }
}
