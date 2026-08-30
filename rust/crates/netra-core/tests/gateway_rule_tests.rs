//! # Gateway Posture Finding Rules Test Suite (Phase 8.7.2)
//!
//! Comprehensive, deterministic test suite for:
//! - `NET-003-GATEWAY-OFF-SUBNET`
//! - `NET-004-COMPETING-DEFAULT-GATEWAYS`
//!
//! Verifies positive detections, negative suppressions, RFC 3021 / 6164 handling,
//! IPv6 link-local semantics, guardrail confidence propagation, deterministic
//! deduplication fingerprinting, and zero raw MAC leakage.

use chrono::Utc;
use netra_core::id::DeviceId;
use netra_core::network::{
    IpClassification, NetworkTopologySnapshot, TopologyGatewayNode, TopologyInterfaceNode,
    TopologyObservationPayload, TopologySubnetRecord,
};
use netra_core::observation::{
    ConfidenceScore, Observation, ObservationPayload, ObservationType, PrivilegeStatus,
    SensitivityLevel, TargetDescriptor,
};
use netra_core::rules::{
    FindingRule, Net003GatewayOffSubnetRule, Net004CompetingGatewaysRule, RuleEngine,
};
use netra_core::storage::FindingSeverity;

fn create_test_topology_obs(
    gateways: Vec<TopologyGatewayNode>,
    subnets: Vec<TopologySubnetRecord>,
    interfaces: Vec<TopologyInterfaceNode>,
    confidence: ConfidenceScore,
    missing_sources: Vec<String>,
    partial_sources: Vec<String>,
) -> Observation {
    Observation::new(
        DeviceId::new(),
        "scanner.topology.v1",
        ObservationType::Topology,
        TargetDescriptor::Host {
            hostname: "agent-node-01".to_string(),
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
            missing_sources,
            partial_sources,
        }),
    )
    .unwrap()
}

// =============================================================================
// NET-003: GATEWAY OUTSIDE SUBNET TESTS
// =============================================================================

#[test]
fn test_net003_off_subnet_ipv4_gateway_emits_medium_finding() {
    let rule = Net003GatewayOffSubnetRule::new();
    let obs = create_test_topology_obs(
        vec![TopologyGatewayNode {
            gateway_ip: "192.168.100.1".to_string(),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 10,
            is_ipv6: false,
        }],
        vec![TopologySubnetRecord {
            network_cidr: "10.0.0.0/24".to_string(),
            interface_name: "eth0".to_string(),
            is_ipv6: false,
            classification: IpClassification::Private,
        }],
        vec![TopologyInterfaceNode {
            name: "eth0".to_string(),
            index: 2,
            is_up: true,
            is_loopback: false,
            ip_addresses: vec!["10.0.0.50".to_string()],
            mac_address_hash: None,
        }],
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        vec![],
        vec![],
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, FindingSeverity::Medium);
    assert_eq!(
        findings[0].title,
        "Default Gateway Address Outside Local Interface Subnet"
    );
    assert_eq!(
        findings[0].discriminator,
        "OFF_SUBNET_GW:192.168.100.1:eth0"
    );

    match &findings[0].target {
        TargetDescriptor::Route {
            destination,
            gateway,
        } => {
            assert_eq!(destination, "0.0.0.0/0");
            assert_eq!(gateway.as_deref(), Some("192.168.100.1"));
        }
        _ => panic!("Expected Route TargetDescriptor"),
    }
}

#[test]
fn test_net003_off_subnet_ipv6_global_gateway_emits_finding() {
    let rule = Net003GatewayOffSubnetRule::new();
    let obs = create_test_topology_obs(
        vec![TopologyGatewayNode {
            gateway_ip: "2001:db8:2::1".to_string(),
            interface_index: 3,
            interface_name: Some("eth1".to_string()),
            metric: 20,
            is_ipv6: true,
        }],
        vec![TopologySubnetRecord {
            network_cidr: "2001:db8:1::/64".to_string(),
            interface_name: "eth1".to_string(),
            is_ipv6: true,
            classification: IpClassification::PublicGlobal,
        }],
        vec![TopologyInterfaceNode {
            name: "eth1".to_string(),
            index: 3,
            is_up: true,
            is_loopback: false,
            ip_addresses: vec!["2001:db8:1::100".to_string()],
            mac_address_hash: None,
        }],
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        vec![],
        vec![],
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, FindingSeverity::Medium);
    assert_eq!(
        findings[0].discriminator,
        "OFF_SUBNET_GW:2001:db8:2::1:eth1"
    );
}

#[test]
fn test_net003_on_subnet_ipv4_gateway_clean() {
    let rule = Net003GatewayOffSubnetRule::new();
    let obs = create_test_topology_obs(
        vec![TopologyGatewayNode {
            gateway_ip: "10.0.0.1".to_string(),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 10,
            is_ipv6: false,
        }],
        vec![TopologySubnetRecord {
            network_cidr: "10.0.0.0/24".to_string(),
            interface_name: "eth0".to_string(),
            is_ipv6: false,
            classification: IpClassification::Private,
        }],
        vec![TopologyInterfaceNode {
            name: "eth0".to_string(),
            index: 2,
            is_up: true,
            is_loopback: false,
            ip_addresses: vec!["10.0.0.50".to_string()],
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
fn test_net003_ipv6_link_local_gateway_clean() {
    let rule = Net003GatewayOffSubnetRule::new();
    let obs = create_test_topology_obs(
        vec![TopologyGatewayNode {
            gateway_ip: "fe80::1".to_string(),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 1024,
            is_ipv6: true,
        }],
        vec![TopologySubnetRecord {
            network_cidr: "2001:db8::/64".to_string(),
            interface_name: "eth0".to_string(),
            is_ipv6: true,
            classification: IpClassification::PublicGlobal,
        }],
        vec![TopologyInterfaceNode {
            name: "eth0".to_string(),
            index: 2,
            is_up: true,
            is_loopback: false,
            ip_addresses: vec!["2001:db8::100".to_string()],
            mac_address_hash: None,
        }],
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        vec![],
        vec![],
    );

    let findings = rule.evaluate(&obs);
    assert!(
        findings.is_empty(),
        "IPv6 link-local default routers must not be flagged"
    );
}

#[test]
fn test_net003_rfc3021_31_subnet_clean() {
    let rule = Net003GatewayOffSubnetRule::new();
    let obs = create_test_topology_obs(
        vec![TopologyGatewayNode {
            gateway_ip: "192.168.1.1".to_string(),
            interface_index: 4,
            interface_name: Some("p2p0".to_string()),
            metric: 10,
            is_ipv6: false,
        }],
        vec![TopologySubnetRecord {
            network_cidr: "192.168.1.0/31".to_string(),
            interface_name: "p2p0".to_string(),
            is_ipv6: false,
            classification: IpClassification::Private,
        }],
        vec![TopologyInterfaceNode {
            name: "p2p0".to_string(),
            index: 4,
            is_up: true,
            is_loopback: false,
            ip_addresses: vec!["192.168.1.0".to_string()],
            mac_address_hash: None,
        }],
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        vec![],
        vec![],
    );

    let findings = rule.evaluate(&obs);
    assert!(
        findings.is_empty(),
        "RFC 3021 /31 subnet default gateway must evaluate clean"
    );
}

#[test]
fn test_net003_rfc6164_127_subnet_clean() {
    let rule = Net003GatewayOffSubnetRule::new();
    let obs = create_test_topology_obs(
        vec![TopologyGatewayNode {
            gateway_ip: "2001:db8::1".to_string(),
            interface_index: 4,
            interface_name: Some("p2p1".to_string()),
            metric: 100,
            is_ipv6: true,
        }],
        vec![TopologySubnetRecord {
            network_cidr: "2001:db8::/127".to_string(),
            interface_name: "p2p1".to_string(),
            is_ipv6: true,
            classification: IpClassification::PublicGlobal,
        }],
        vec![TopologyInterfaceNode {
            name: "p2p1".to_string(),
            index: 4,
            is_up: true,
            is_loopback: false,
            ip_addresses: vec!["2001:db8::0".to_string()],
            mac_address_hash: None,
        }],
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        vec![],
        vec![],
    );

    let findings = rule.evaluate(&obs);
    assert!(
        findings.is_empty(),
        "RFC 6164 /127 subnet default gateway must evaluate clean"
    );
}

#[test]
fn test_net003_guardrail_missing_interfaces_suppresses() {
    let rule = Net003GatewayOffSubnetRule::new();
    let obs = create_test_topology_obs(
        vec![TopologyGatewayNode {
            gateway_ip: "192.168.100.1".to_string(),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 10,
            is_ipv6: false,
        }],
        vec![],
        vec![],
        ConfidenceScore::UNPRIVILEGED_PARTIAL,
        vec!["scanner.interfaces.v1".to_string()], // Missing interfaces source
        vec![],
    );

    let findings = rule.evaluate(&obs);
    assert!(
        findings.is_empty(),
        "Missing interfaces source must suppress NET-003"
    );
}

#[test]
fn test_net003_guardrail_partial_interfaces_downgrades_to_low() {
    let rule = Net003GatewayOffSubnetRule::new();
    let obs = create_test_topology_obs(
        vec![TopologyGatewayNode {
            gateway_ip: "192.168.100.1".to_string(),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 10,
            is_ipv6: false,
        }],
        vec![TopologySubnetRecord {
            network_cidr: "10.0.0.0/24".to_string(),
            interface_name: "eth0".to_string(),
            is_ipv6: false,
            classification: IpClassification::Private,
        }],
        vec![TopologyInterfaceNode {
            name: "eth0".to_string(),
            index: 2,
            is_up: true,
            is_loopback: false,
            ip_addresses: vec!["10.0.0.50".to_string()],
            mac_address_hash: None,
        }],
        ConfidenceScore::SYSTEM_TABLE,
        vec![],
        vec!["scanner.interfaces.v1".to_string()], // Partial interfaces source
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].severity,
        FindingSeverity::Low,
        "Partial source must downgrade severity to Low"
    );
}

// =============================================================================
// NET-004: COMPETING DEFAULT GATEWAYS TESTS
// =============================================================================

#[test]
fn test_net004_equal_metric_different_interfaces_emits_finding() {
    let rule = Net004CompetingGatewaysRule::new();
    let obs = create_test_topology_obs(
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
        vec![],
        vec![],
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        vec![],
        vec![],
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, FindingSeverity::Low);
    assert_eq!(
        findings[0].title,
        "Equal-Metric Competing Default Gateways Detected"
    );
    assert_eq!(
        findings[0].discriminator,
        "EQUAL_METRIC_GW:IPv4:25:10.0.0.1_192.168.1.1"
    );

    match &findings[0].target {
        TargetDescriptor::Host { hostname } => {
            assert_eq!(hostname, "agent-node-01");
        }
        _ => panic!("Expected Host TargetDescriptor"),
    }
}

#[test]
fn test_net004_equal_metric_same_interface_emits_finding() {
    let rule = Net004CompetingGatewaysRule::new();
    let obs = create_test_topology_obs(
        vec![
            TopologyGatewayNode {
                gateway_ip: "192.168.1.1".to_string(),
                interface_index: 1,
                interface_name: Some("eth0".to_string()),
                metric: 20,
                is_ipv6: false,
            },
            TopologyGatewayNode {
                gateway_ip: "192.168.1.254".to_string(),
                interface_index: 1,
                interface_name: Some("eth0".to_string()),
                metric: 20,
                is_ipv6: false,
            },
        ],
        vec![],
        vec![],
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        vec![],
        vec![],
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, FindingSeverity::Low);
    assert_eq!(
        findings[0].discriminator,
        "EQUAL_METRIC_GW:IPv4:20:192.168.1.1_192.168.1.254"
    );
}

#[test]
fn test_net004_single_default_gateway_clean() {
    let rule = Net004CompetingGatewaysRule::new();
    let obs = create_test_topology_obs(
        vec![TopologyGatewayNode {
            gateway_ip: "192.168.1.1".to_string(),
            interface_index: 1,
            interface_name: Some("eth0".to_string()),
            metric: 10,
            is_ipv6: false,
        }],
        vec![],
        vec![],
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        vec![],
        vec![],
    );

    let findings = rule.evaluate(&obs);
    assert!(
        findings.is_empty(),
        "Single default gateway must evaluate clean"
    );
}

#[test]
fn test_net004_distinct_metrics_failover_clean() {
    let rule = Net004CompetingGatewaysRule::new();
    let obs = create_test_topology_obs(
        vec![
            TopologyGatewayNode {
                gateway_ip: "192.168.1.1".to_string(),
                interface_index: 1,
                interface_name: Some("eth0".to_string()),
                metric: 10, // Primary gateway
                is_ipv6: false,
            },
            TopologyGatewayNode {
                gateway_ip: "10.0.0.1".to_string(),
                interface_index: 2,
                interface_name: Some("wlan0".to_string()),
                metric: 50, // Backup gateway (different metric)
                is_ipv6: false,
            },
        ],
        vec![],
        vec![],
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        vec![],
        vec![],
    );

    let findings = rule.evaluate(&obs);
    assert!(
        findings.is_empty(),
        "Distinct metrics represent unambiguous failover hierarchy and must not be flagged"
    );
}

#[test]
fn test_net004_dual_stack_single_v4_single_v6_clean() {
    let rule = Net004CompetingGatewaysRule::new();
    let obs = create_test_topology_obs(
        vec![
            TopologyGatewayNode {
                gateway_ip: "192.168.1.1".to_string(),
                interface_index: 1,
                interface_name: Some("eth0".to_string()),
                metric: 25,
                is_ipv6: false,
            },
            TopologyGatewayNode {
                gateway_ip: "2001:db8::1".to_string(),
                interface_index: 1,
                interface_name: Some("eth0".to_string()),
                metric: 25,
                is_ipv6: true,
            },
        ],
        vec![],
        vec![],
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        vec![],
        vec![],
    );

    let findings = rule.evaluate(&obs);
    assert!(
        findings.is_empty(),
        "Independent IPv4 and IPv6 gateways with identical metrics must not compete"
    );
}

#[test]
fn test_net004_vpn_override_metric_clean() {
    let rule = Net004CompetingGatewaysRule::new();
    let obs = create_test_topology_obs(
        vec![
            TopologyGatewayNode {
                gateway_ip: "10.8.0.1".to_string(),
                interface_index: 5,
                interface_name: Some("tun0".to_string()),
                metric: 5, // VPN lower metric override
                is_ipv6: false,
            },
            TopologyGatewayNode {
                gateway_ip: "192.168.1.1".to_string(),
                interface_index: 1,
                interface_name: Some("eth0".to_string()),
                metric: 25, // Physical LAN
                is_ipv6: false,
            },
        ],
        vec![],
        vec![],
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        vec![],
        vec![],
    );

    let findings = rule.evaluate(&obs);
    assert!(
        findings.is_empty(),
        "VPN intentional metric override is not an equal-metric conflict"
    );
}

#[test]
fn test_net004_guardrail_missing_routes_suppresses() {
    let rule = Net004CompetingGatewaysRule::new();
    let obs = create_test_topology_obs(
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
        vec![],
        vec![],
        ConfidenceScore::HEURISTIC,
        vec!["scanner.routes.v1".to_string()], // Missing routes source
        vec![],
    );

    let findings = rule.evaluate(&obs);
    assert!(
        findings.is_empty(),
        "Missing routes source must suppress NET-004"
    );
}

// =============================================================================
// INVARIANTS & ENGINE INTEGRATION TESTS
// =============================================================================

#[test]
fn test_privacy_and_fingerprint_invariants() {
    let engine = RuleEngine::with_all_rules();

    let obs = create_test_topology_obs(
        vec![
            TopologyGatewayNode {
                gateway_ip: "192.168.100.1".to_string(),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                metric: 25,
                is_ipv6: false,
            },
            TopologyGatewayNode {
                gateway_ip: "10.0.0.1".to_string(),
                interface_index: 3,
                interface_name: Some("wlan0".to_string()),
                metric: 25,
                is_ipv6: false,
            },
        ],
        vec![
            TopologySubnetRecord {
                network_cidr: "192.168.10.0/24".to_string(),
                interface_name: "eth0".to_string(),
                is_ipv6: false,
                classification: IpClassification::Private,
            },
            TopologySubnetRecord {
                network_cidr: "10.0.0.0/24".to_string(),
                interface_name: "wlan0".to_string(),
                is_ipv6: false,
                classification: IpClassification::Private,
            },
        ],
        vec![
            TopologyInterfaceNode {
                name: "eth0".to_string(),
                index: 2,
                is_up: true,
                is_loopback: false,
                ip_addresses: vec!["192.168.10.50".to_string()],
                mac_address_hash: Some("abc123pseudo".to_string()),
            },
            TopologyInterfaceNode {
                name: "wlan0".to_string(),
                index: 3,
                is_up: true,
                is_loopback: false,
                ip_addresses: vec!["10.0.0.50".to_string()],
                mac_address_hash: Some("def456pseudo".to_string()),
            },
        ],
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        vec![],
        vec![],
    );

    let findings_1 = engine.evaluate(&obs);
    let findings_2 = engine.evaluate(&obs);

    // Both NET-003 and NET-004 should trigger
    assert_eq!(findings_1.len(), 2);
    assert_eq!(findings_2.len(), 2);

    // Verify SHA-256 fingerprint determinism
    for i in 0..findings_1.len() {
        assert_eq!(findings_1[i].fingerprint, findings_2[i].fingerprint);
        assert_eq!(findings_1[i].rule_id, findings_2[i].rule_id);

        // Verify zero raw MAC addresses in evidence JSON string representation
        let evidence_str = &findings_1[i].evidence_summary_json;
        assert!(
            !evidence_str.contains("00:"),
            "Evidence must not contain raw MAC colons"
        );
        assert!(
            !evidence_str.contains("mac_address"),
            "Evidence must not expose raw MAC field"
        );
    }
}
