//! # Network Posture Rule Registry
//!
//! Registry and lifecycle management for platform-neutral network security finding rules.

use std::sync::Arc;

use serde::Serialize;

use crate::observation::ObservationType;
use crate::rules::engine::RuleEngine;
use crate::rules::traits::FindingRule;
use crate::storage::FindingSeverity;

/// Common metadata descriptor for network security posture evaluation rules.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct NetworkRuleMetadata {
    /// Unique rule identifier (e.g. `NET-003-ROGUE-GATEWAY`).
    pub rule_id: &'static str,
    /// Schema/rule version.
    pub version: u32,
    /// Observation domain evaluated by this rule.
    pub domain: ObservationType,
    /// Default finding severity assigned when a violation is detected.
    pub default_severity: FindingSeverity,
    /// Human-readable title for the finding.
    pub title: &'static str,
    /// Concise description of the security risk.
    pub description: &'static str,
    /// Prescriptive remediation guidance.
    pub remediation_guidance: &'static str,
    /// List of scanner sources required for reliable rule evaluation.
    pub required_sources: &'static [&'static str],
    /// Minimum confidence threshold required to emit finding at default severity.
    pub min_confidence: f64,
}

/// Registry holding active network security posture rules.
#[derive(Default)]
pub struct NetworkRuleRegistry {
    rules: Vec<Arc<dyn FindingRule>>,
}

impl NetworkRuleRegistry {
    /// Creates a new empty network rule registry.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Registers a network finding rule into the registry.
    pub fn register_rule(&mut self, rule: Arc<dyn FindingRule>) {
        self.rules.push(rule);
    }

    /// Returns a slice of all registered network rules.
    pub fn rules(&self) -> &[Arc<dyn FindingRule>] {
        &self.rules
    }

    /// Consumes the registry and returns the registered rules.
    pub fn into_rules(self) -> Vec<Arc<dyn FindingRule>> {
        self.rules
    }

    /// Registers all rules from this registry into an existing [`RuleEngine`].
    pub fn register_into_engine(&self, engine: &mut RuleEngine) {
        for rule in &self.rules {
            engine.register_rule(Arc::clone(rule));
        }
    }
}

/// Creates and returns all active network security posture rules (Phase 8.7).
pub fn create_all_network_rules() -> Vec<Arc<dyn FindingRule>> {
    let mut registry = NetworkRuleRegistry::new();
    // Phase 8.7.2: Gateway posture rules
    registry.register_rule(Arc::new(
        crate::rules::network::net_003::Net003GatewayOffSubnetRule::new(),
    ));
    registry.register_rule(Arc::new(
        crate::rules::network::net_004::Net004CompetingGatewaysRule::new(),
    ));
    // Phase 8.7.3: DNS & Routing posture rules
    registry.register_rule(Arc::new(
        crate::rules::network::net_005::Net005InvalidDnsResolverRule::new(),
    ));
    registry.register_rule(Arc::new(
        crate::rules::network::net_006::Net006LoopbackRouteLeakRule::new(),
    ));
    // Phase 8.7.4: Neighbor & Multi-Homing posture rules
    registry.register_rule(Arc::new(
        crate::rules::network::net_007::Net007InvalidNeighborEntryRule::new(),
    ));
    registry.register_rule(Arc::new(
        crate::rules::network::net_008::Net008MultiHomedPublicPrivateRule::new(),
    ));
    registry.into_rules()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::{Observation, ObservationPayload, TargetDescriptor};
    use crate::rules::traits::RawFinding;

    struct DummyNetworkRule;

    impl FindingRule for DummyNetworkRule {
        fn rule_id(&self) -> &'static str {
            "NET-TEST-001"
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

        fn evaluate(&self, _obs: &Observation) -> Vec<RawFinding> {
            vec![]
        }
    }

    #[test]
    fn test_network_rule_registry_registration() {
        let mut registry = NetworkRuleRegistry::new();
        assert_eq!(registry.rules().len(), 0);

        registry.register_rule(Arc::new(DummyNetworkRule));
        assert_eq!(registry.rules().len(), 1);
        assert_eq!(registry.rules()[0].rule_id(), "NET-TEST-001");
    }

    #[test]
    fn test_network_rule_registry_into_engine() {
        let mut registry = NetworkRuleRegistry::new();
        registry.register_rule(Arc::new(DummyNetworkRule));

        let mut engine = RuleEngine::new();
        registry.register_into_engine(&mut engine);

        let obs = Observation::new(
            crate::id::DeviceId::new(),
            "scanner.topology.v1",
            ObservationType::Topology,
            TargetDescriptor::Host {
                hostname: "host".to_string(),
            },
            10,
            crate::observation::PrivilegeStatus::Available,
            crate::observation::ConfidenceScore::KERNEL_AUTHORITATIVE,
            crate::observation::SensitivityLevel::Public,
            ObservationPayload::Topology(crate::network::topology::TopologyObservationPayload {
                snapshot: crate::network::topology::NetworkTopologySnapshot {
                    schema_version: 1,
                    device_id: crate::id::DeviceId::new(),
                    generated_at: chrono::Utc::now(),
                    interfaces: vec![],
                    default_gateways: vec![],
                    dns_resolvers: vec![],
                    neighbors: vec![],
                    subnets: vec![],
                    is_multi_homed: false,
                    confidence: crate::observation::ConfidenceScore::KERNEL_AUTHORITATIVE,
                    provenance_sources: vec![],
                },
                edges: vec![],
                missing_sources: vec![],
                partial_sources: vec![],
            }),
        )
        .unwrap();

        let findings = engine.evaluate(&obs);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_create_all_network_rules_returns_registered_rules() {
        let rules = create_all_network_rules();
        assert_eq!(rules.len(), 6);
        assert_eq!(rules[0].rule_id(), "NET-003-GATEWAY-OFF-SUBNET");
        assert_eq!(rules[1].rule_id(), "NET-004-COMPETING-DEFAULT-GATEWAYS");
        assert_eq!(rules[2].rule_id(), "NET-005-INVALID-DNS-RESOLVER");
        assert_eq!(rules[3].rule_id(), "NET-006-LOOPBACK-ROUTE-LEAK");
        assert_eq!(rules[4].rule_id(), "NET-007-INVALID-NEIGHBOR-ENTRY");
        assert_eq!(rules[5].rule_id(), "NET-008-MULTI-HOMED-PUBLIC-PRIVATE");
    }
}
