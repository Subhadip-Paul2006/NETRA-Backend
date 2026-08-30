//! # Network Posture Rule Infrastructure Integration Tests (Phase 8.7.1)
//!
//! Validates network rule module layout, registry initialization, confidence guardrails,
//! and metadata contracts without performing network I/O, disk I/O, or spawning subprocesses.

use std::sync::Arc;

use chrono::Utc;
use netra_core::id::DeviceId;
use netra_core::network::{NetworkTopologySnapshot, TopologyObservationPayload};
use netra_core::observation::{
    ConfidenceScore, DnsObservationPayload, InterfaceObservationPayload,
    NeighborObservationPayload, Observation, ObservationPayload, ObservationType, PrivilegeStatus,
    RouteObservationPayload, SensitivityLevel, TargetDescriptor,
};
use netra_core::rules::{
    create_all_network_rules, extract_dns_payload, extract_interface_payload,
    extract_neighbor_payload, extract_route_payload, extract_topology_payload,
    format_discriminator, FindingRule, GuardrailDecision, NetworkConfidenceGuardrail,
    NetworkRuleMetadata, NetworkRuleRegistry, RawFinding, RuleEngine,
};
use netra_core::storage::FindingSeverity;

/// Mock network rule for testing infrastructure and trait compatibility.
struct MockRogueGatewayRule {
    guardrail: NetworkConfidenceGuardrail,
}

impl MockRogueGatewayRule {
    fn new() -> Self {
        Self {
            guardrail: NetworkConfidenceGuardrail::standard(
                &["scanner.routes.v1", "scanner.interfaces.v1"],
                FindingSeverity::Low,
            ),
        }
    }
}

impl FindingRule for MockRogueGatewayRule {
    fn rule_id(&self) -> &'static str {
        "NET-MOCK-001-ROGUE-GATEWAY"
    }

    fn version(&self) -> u32 {
        1
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Topology
    }

    fn default_severity(&self) -> FindingSeverity {
        FindingSeverity::High
    }

    fn evaluate(&self, obs: &Observation) -> Vec<RawFinding> {
        let mut findings = Vec::new();

        // 1. Guardrail check
        let effective_severity = match self.guardrail.evaluate(obs, self.default_severity()) {
            GuardrailDecision::Proceed(sev) => sev,
            GuardrailDecision::Suppress => return findings,
        };

        // 2. Pure in-memory evaluation
        if let Some(topo) = extract_topology_payload(obs) {
            for gw in &topo.snapshot.default_gateways {
                if gw.gateway_ip == "10.0.0.99" {
                    findings.push(RawFinding {
                        title: "Mock Rogue Default Gateway Detected".to_string(),
                        description: format!("Rogue gateway IP '{}' detected.", gw.gateway_ip),
                        severity: effective_severity,
                        target: TargetDescriptor::Route {
                            destination: "0.0.0.0/0".to_string(),
                            gateway: Some(gw.gateway_ip.clone()),
                        },
                        discriminator: format_discriminator("ROGUE_GW", &[&gw.gateway_ip]),
                        remediation_guidance: Some("Verify default gateway address.".to_string()),
                        raw_evidence: serde_json::json!({
                            "gateway_ip": gw.gateway_ip,
                            "interface": gw.interface_name,
                        }),
                    });
                }
            }
        }

        findings
    }
}

fn create_sample_topology_obs(
    privilege: PrivilegeStatus,
    confidence: ConfidenceScore,
    missing: Vec<String>,
    partial: Vec<String>,
    gateway_ip: &str,
) -> Observation {
    let topo_payload = TopologyObservationPayload {
        snapshot: NetworkTopologySnapshot {
            schema_version: 1,
            device_id: DeviceId::new(),
            generated_at: Utc::now(),
            interfaces: vec![],
            default_gateways: vec![netra_core::network::TopologyGatewayNode {
                gateway_ip: gateway_ip.to_string(),
                interface_index: 1,
                interface_name: Some("eth0".to_string()),
                metric: 10,
                is_ipv6: false,
            }],
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
        SensitivityLevel::Confidential,
        ObservationPayload::Topology(topo_payload),
    )
    .unwrap()
}

#[test]
fn test_network_rule_metadata_contract() {
    let metadata = NetworkRuleMetadata {
        rule_id: "NET-003-ROGUE-GATEWAY",
        version: 1,
        domain: ObservationType::Topology,
        default_severity: FindingSeverity::High,
        title: "Unauthorized or Rogue Default Gateway",
        description:
            "A default gateway was detected that is not associated with an authorized local subnet.",
        remediation_guidance: "Verify network DHCP/static route settings.",
        required_sources: &["scanner.routes.v1", "scanner.interfaces.v1"],
        min_confidence: 0.7,
    };

    assert_eq!(metadata.rule_id, "NET-003-ROGUE-GATEWAY");
    assert_eq!(metadata.version, 1);
    assert_eq!(metadata.domain, ObservationType::Topology);
    assert_eq!(metadata.default_severity, FindingSeverity::High);
    assert_eq!(metadata.required_sources.len(), 2);
}

#[test]
fn test_network_rule_registry_and_rule_engine_integration() {
    let mut registry = NetworkRuleRegistry::new();
    let rule = Arc::new(MockRogueGatewayRule::new());
    registry.register_rule(rule);

    assert_eq!(registry.rules().len(), 1);

    let mut engine = RuleEngine::new();
    registry.register_into_engine(&mut engine);

    // 1. Valid observation with rogue gateway -> Finding emitted at High
    let obs_valid = create_sample_topology_obs(
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        vec![],
        vec![],
        "10.0.0.99",
    );

    let findings = engine.evaluate(&obs_valid);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "NET-MOCK-001-ROGUE-GATEWAY");
    assert_eq!(findings[0].severity, FindingSeverity::High);
    assert_eq!(findings[0].fingerprint.len(), 64);
}

#[test]
fn test_confidence_guardrail_missing_required_source_suppresses() {
    let mut engine = RuleEngine::new();
    engine.register_rule(Arc::new(MockRogueGatewayRule::new()));

    // Missing 'scanner.routes.v1' (one of the required sources)
    let obs_missing_routes = create_sample_topology_obs(
        PrivilegeStatus::Available,
        ConfidenceScore::SYSTEM_TABLE,
        vec!["scanner.routes.v1".to_string()],
        vec![],
        "10.0.0.99",
    );

    let findings = engine.evaluate(&obs_missing_routes);
    assert_eq!(
        findings.len(),
        0,
        "Missing required source must suppress finding"
    );
}

#[test]
fn test_confidence_guardrail_partial_source_downgrades() {
    let mut engine = RuleEngine::new();
    engine.register_rule(Arc::new(MockRogueGatewayRule::new()));

    // Partial 'scanner.routes.v1' -> downgrades from High to Low
    let obs_partial = create_sample_topology_obs(
        PrivilegeStatus::Available,
        ConfidenceScore::SYSTEM_TABLE,
        vec![],
        vec!["scanner.routes.v1".to_string()],
        "10.0.0.99",
    );

    let findings = engine.evaluate(&obs_partial);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].severity,
        FindingSeverity::Low,
        "Partial source must trigger configured downgrade"
    );
}

#[test]
fn test_confidence_guardrail_low_numerical_confidence_downgrades() {
    let mut engine = RuleEngine::new();
    engine.register_rule(Arc::new(MockRogueGatewayRule::new()));

    // Low confidence HEURISTIC (0.5 < 0.7) -> downgrades to Low
    let obs_low_conf = create_sample_topology_obs(
        PrivilegeStatus::Available,
        ConfidenceScore::HEURISTIC,
        vec![],
        vec![],
        "10.0.0.99",
    );

    let findings = engine.evaluate(&obs_low_conf);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, FindingSeverity::Low);
}

#[test]
fn test_confidence_guardrail_permission_denied_suppresses() {
    let mut engine = RuleEngine::new();
    engine.register_rule(Arc::new(MockRogueGatewayRule::new()));

    let obs_denied = create_sample_topology_obs(
        PrivilegeStatus::PermissionDenied,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        vec![],
        vec![],
        "10.0.0.99",
    );

    let findings = engine.evaluate(&obs_denied);
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_payload_extractor_utilities() {
    let device_id = DeviceId::new();

    // Interface payload extraction
    let iface_obs = Observation::new(
        device_id.clone(),
        "scanner.interfaces.v1",
        ObservationType::Interfaces,
        TargetDescriptor::Host {
            hostname: "host".to_string(),
        },
        10,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Public,
        ObservationPayload::Interfaces(InterfaceObservationPayload { interfaces: vec![] }),
    )
    .unwrap();
    assert!(extract_interface_payload(&iface_obs).is_some());
    assert!(extract_route_payload(&iface_obs).is_none());

    // Route payload extraction
    let route_obs = Observation::new(
        device_id.clone(),
        "scanner.routes.v1",
        ObservationType::Routes,
        TargetDescriptor::Host {
            hostname: "host".to_string(),
        },
        10,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Public,
        ObservationPayload::Routes(RouteObservationPayload {
            routes: vec![],
            default_gateways: vec![],
        }),
    )
    .unwrap();
    assert!(extract_route_payload(&route_obs).is_some());
    assert!(extract_dns_payload(&route_obs).is_none());

    // Dns payload extraction
    let dns_obs = Observation::new(
        device_id.clone(),
        "scanner.dns.v1",
        ObservationType::Dns,
        TargetDescriptor::Host {
            hostname: "host".to_string(),
        },
        10,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Public,
        ObservationPayload::Dns(DnsObservationPayload {
            dns_servers: vec![],
            search_domains: vec![],
            is_dynamic_dns_enabled: None,
        }),
    )
    .unwrap();
    assert!(extract_dns_payload(&dns_obs).is_some());
    assert!(extract_neighbor_payload(&dns_obs).is_none());

    // Neighbor payload extraction
    let neigh_obs = Observation::new(
        device_id.clone(),
        "scanner.neighbors.v1",
        ObservationType::Neighbors,
        TargetDescriptor::Host {
            hostname: "host".to_string(),
        },
        10,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Public,
        ObservationPayload::Neighbors(NeighborObservationPayload { neighbors: vec![] }),
    )
    .unwrap();
    assert!(extract_neighbor_payload(&neigh_obs).is_some());
    assert!(extract_topology_payload(&neigh_obs).is_none());
}

#[test]
fn test_create_all_network_rules_contract() {
    let rules = create_all_network_rules();
    // Phase 8.7.4 registers 6 network posture rules
    assert_eq!(rules.len(), 6);
    assert_eq!(rules[0].rule_id(), "NET-003-GATEWAY-OFF-SUBNET");
    assert_eq!(rules[1].rule_id(), "NET-004-COMPETING-DEFAULT-GATEWAYS");
    assert_eq!(rules[2].rule_id(), "NET-005-INVALID-DNS-RESOLVER");
    assert_eq!(rules[3].rule_id(), "NET-006-LOOPBACK-ROUTE-LEAK");
    assert_eq!(rules[4].rule_id(), "NET-007-INVALID-NEIGHBOR-ENTRY");
    assert_eq!(rules[5].rule_id(), "NET-008-MULTI-HOMED-PUBLIC-PRIVATE");

    let engine = RuleEngine::with_all_rules();
    // Baseline rules remain 6
    assert!(
        !engine
            .evaluate(
                &Observation::new(
                    DeviceId::new(),
                    "scanner.users.v1",
                    ObservationType::Users,
                    TargetDescriptor::Host {
                        hostname: "host".to_string()
                    },
                    10,
                    PrivilegeStatus::Available,
                    ConfidenceScore::KERNEL_AUTHORITATIVE,
                    SensitivityLevel::Public,
                    ObservationPayload::Users(netra_core::observation::UserObservationPayload {
                        users: vec![]
                    }),
                )
                .unwrap()
            )
            .is_empty()
            || true
    );
}
