//! # Neighbor & Multi-Homing Finding Rules Integration Tests (Phase 8.7.4)
//!
//! Validates `NET-007-INVALID-NEIGHBOR-ENTRY` and `NET-008-MULTI-HOMED-PUBLIC-PRIVATE`
//! rules against all 16 specification vectors, privacy boundaries, and deterministic
//! fingerprint contracts without disk I/O, network I/O, or subprocess execution.

use std::sync::Arc;

use chrono::Utc;
use netra_core::id::DeviceId;
use netra_core::network::{
    IpClassification, NetworkTopologySnapshot, TopologyGatewayNode, TopologyInterfaceNode,
    TopologyObservationPayload, TopologySubnetRecord,
};
use netra_core::observation::{
    ConfidenceScore, NeighborObservationPayload, NeighborRecord, NeighborState, Observation,
    ObservationPayload, ObservationType, PrivilegeStatus, SensitivityLevel, TargetDescriptor,
};
use netra_core::rules::{
    FindingRule, Net007InvalidNeighborEntryRule, Net008MultiHomedPublicPrivateRule, RuleEngine,
};
use netra_core::storage::FindingSeverity;

// ============================================================================
// HELPER CONSTRUCTORS
// ============================================================================

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

fn make_topology_observation(
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

// ============================================================================
// VECTOR 1 - 8: NET-007 INVALID NEIGHBOR ENTRY TESTS
// ============================================================================

#[test]
fn test_vector_01_net007_normal_unicast_neighbors_clean() {
    let rule = Net007InvalidNeighborEntryRule::new();
    let obs = make_neighbor_observation(
        vec![
            NeighborRecord {
                ip_address: "192.168.1.1".to_string(),
                mac_address_hash: Some("a1b2c3d4e5f6".to_string()),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                state: NeighborState::Reachable,
                is_ipv6: false,
                ip_classification: IpClassification::Private,
                is_router: Some(true),
            },
            NeighborRecord {
                ip_address: "10.0.0.50".to_string(),
                mac_address_hash: Some("f6e5d4c3b2a1".to_string()),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                state: NeighborState::Stale,
                is_ipv6: false,
                ip_classification: IpClassification::Private,
                is_router: None,
            },
            NeighborRecord {
                ip_address: "fe80::1".to_string(),
                mac_address_hash: Some("112233445566".to_string()),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                state: NeighborState::Reachable,
                is_ipv6: true,
                ip_classification: IpClassification::LinkLocal,
                is_router: Some(true),
            },
            NeighborRecord {
                ip_address: "93.184.216.34".to_string(),
                mac_address_hash: Some("998877665544".to_string()),
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
        "Vector 1: Normal unicast neighbors in Reachable or Stale states must evaluate clean"
    );
}

#[test]
fn test_vector_02_net007_unspecified_ipv4_finding() {
    let rule = Net007InvalidNeighborEntryRule::new();
    let obs = make_neighbor_observation(
        vec![NeighborRecord {
            ip_address: "0.0.0.0".to_string(),
            mac_address_hash: None,
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            state: NeighborState::Permanent,
            is_ipv6: false,
            ip_classification: IpClassification::Unspecified,
            is_router: None,
        }],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(
        findings.len(),
        1,
        "Vector 2: Unspecified IPv4 must emit 1 finding"
    );
    assert_eq!(findings[0].severity, FindingSeverity::Low);
    assert_eq!(findings[0].target.target_key(), "neighbor:eth0:0.0.0.0");
    assert_eq!(
        findings[0].discriminator,
        "INVALID_NEIGHBOR:0.0.0.0:UNSPECIFIED"
    );
}

#[test]
fn test_vector_03_net007_unspecified_ipv6_finding() {
    let rule = Net007InvalidNeighborEntryRule::new();
    let obs = make_neighbor_observation(
        vec![NeighborRecord {
            ip_address: "::".to_string(),
            mac_address_hash: None,
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            state: NeighborState::Permanent,
            is_ipv6: true,
            ip_classification: IpClassification::Unspecified,
            is_router: None,
        }],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(
        findings.len(),
        1,
        "Vector 3: Unspecified IPv6 must emit 1 finding"
    );
    assert_eq!(findings[0].target.target_key(), "neighbor:eth0:::");
    assert_eq!(findings[0].discriminator, "INVALID_NEIGHBOR::::UNSPECIFIED");
}

#[test]
fn test_vector_04_net007_broadcast_ipv4_finding() {
    let rule = Net007InvalidNeighborEntryRule::new();
    let obs = make_neighbor_observation(
        vec![NeighborRecord {
            ip_address: "255.255.255.255".to_string(),
            mac_address_hash: None,
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            state: NeighborState::Permanent,
            is_ipv6: false,
            ip_classification: IpClassification::Broadcast,
            is_router: None,
        }],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(
        findings.len(),
        1,
        "Vector 4: Broadcast IP must emit 1 finding"
    );
    assert_eq!(
        findings[0].target.target_key(),
        "neighbor:eth0:255.255.255.255"
    );
    assert_eq!(
        findings[0].discriminator,
        "INVALID_NEIGHBOR:255.255.255.255:BROADCAST"
    );
}

#[test]
fn test_vector_05_net007_multicast_ipv4_ipv6_findings() {
    let rule = Net007InvalidNeighborEntryRule::new();
    let obs = make_neighbor_observation(
        vec![
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
                ip_address: "ff02::1".to_string(),
                mac_address_hash: None,
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                state: NeighborState::Permanent,
                is_ipv6: true,
                ip_classification: IpClassification::Multicast,
                is_router: None,
            },
        ],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(
        findings.len(),
        2,
        "Vector 5: Multicast IPv4 & IPv6 must emit 2 findings"
    );
    assert_eq!(findings[0].target.target_key(), "neighbor:eth0:224.0.0.1");
    assert_eq!(findings[1].target.target_key(), "neighbor:eth0:ff02::1");
}

#[test]
fn test_vector_06_net007_loopback_ipv4_ipv6_findings() {
    let rule = Net007InvalidNeighborEntryRule::new();
    let obs = make_neighbor_observation(
        vec![
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
            NeighborRecord {
                ip_address: "::1".to_string(),
                mac_address_hash: None,
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                state: NeighborState::Permanent,
                is_ipv6: true,
                ip_classification: IpClassification::Loopback,
                is_router: None,
            },
        ],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(
        findings.len(),
        2,
        "Vector 6: Loopback entries must emit 2 findings"
    );
    assert_eq!(findings[0].target.target_key(), "neighbor:eth0:127.0.0.1");
    assert_eq!(findings[1].target.target_key(), "neighbor:eth0:::1");
}

#[test]
fn test_vector_07_net007_missing_source_suppressed() {
    let rule = Net007InvalidNeighborEntryRule::new();
    let mut obs = make_neighbor_observation(
        vec![NeighborRecord {
            ip_address: "224.0.0.1".to_string(),
            mac_address_hash: None,
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            state: NeighborState::Permanent,
            is_ipv6: false,
            ip_classification: IpClassification::Multicast,
            is_router: None,
        }],
        PrivilegeStatus::PermissionDenied,
        ConfidenceScore(0.1),
    );
    obs.scanner_id = "scanner.dummy.v1".to_string();

    let findings = rule.evaluate(&obs);
    assert!(
        findings.is_empty(),
        "Vector 7: Permission denied / missing source must suppress findings"
    );
}

#[test]
fn test_vector_08_net007_partial_source_downgrade() {
    let rule = Net007InvalidNeighborEntryRule::new();
    let obs = make_neighbor_observation(
        vec![NeighborRecord {
            ip_address: "224.0.0.1".to_string(),
            mac_address_hash: None,
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            state: NeighborState::Permanent,
            is_ipv6: false,
            ip_classification: IpClassification::Multicast,
            is_router: None,
        }],
        PrivilegeStatus::Partial,
        ConfidenceScore(0.6),
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(
        findings.len(),
        1,
        "Vector 8: Partial source evaluates with Low severity"
    );
    assert_eq!(findings[0].severity, FindingSeverity::Low);
}

// ============================================================================
// VECTOR 9 - 16: NET-008 MULTI-HOMED PUBLIC PRIVATE TESTS
// ============================================================================

#[test]
fn test_vector_09_net008_single_physical_interface_clean() {
    let rule = Net008MultiHomedPublicPrivateRule::new();
    let obs = make_topology_observation(
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
    assert!(
        findings.is_empty(),
        "Vector 9: Single interface must evaluate clean"
    );
}

#[test]
fn test_vector_10_net008_multiple_private_physical_interfaces_clean() {
    let rule = Net008MultiHomedPublicPrivateRule::new();
    let obs = make_topology_observation(
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
        "Vector 10: Multiple private subnets without public interface must evaluate clean"
    );
}

#[test]
fn test_vector_11_net008_physical_and_docker_wsl_virtual_clean() {
    let rule = Net008MultiHomedPublicPrivateRule::new();
    let obs = make_topology_observation(
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
        "Vector 11: Virtual adapters (Docker, WSL) must be excluded from multi-homing alerts"
    );
}

#[test]
fn test_vector_12_net008_physical_and_vpn_clean() {
    let rule = Net008MultiHomedPublicPrivateRule::new();
    let obs = make_topology_observation(
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
                name: "wg0".to_string(),
                index: 3,
                is_up: true,
                is_loopback: false,
                ip_addresses: vec!["10.8.0.2".to_string()],
                mac_address_hash: None,
            },
            TopologyInterfaceNode {
                name: "tun0".to_string(),
                index: 4,
                is_up: true,
                is_loopback: false,
                ip_addresses: vec!["10.9.0.2".to_string()],
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
                network_cidr: "10.8.0.0/24".to_string(),
                interface_name: "wg0".to_string(),
                is_ipv6: false,
                classification: IpClassification::Private,
            },
            TopologySubnetRecord {
                network_cidr: "10.9.0.0/24".to_string(),
                interface_name: "tun0".to_string(),
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
        "Vector 12: VPN tunnels (wg0, tun0) must be excluded from multi-homing alerts"
    );
}

#[test]
fn test_vector_13_net008_documentation_address_plus_private_clean() {
    let rule = Net008MultiHomedPublicPrivateRule::new();
    // 198.51.100.25 (TEST-NET-2) is Documentation, not PublicGlobal
    let obs = make_topology_observation(
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
        "Vector 13: Documentation addresses (198.51.100.0/24) must NOT trigger PublicGlobal multi-homing findings"
    );
}

#[test]
fn test_vector_14_net008_real_public_global_plus_private_physical_finding() {
    let rule = Net008MultiHomedPublicPrivateRule::new();
    let obs = make_topology_observation(
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
    assert_eq!(
        findings.len(),
        1,
        "Vector 14: Concurrent physical PublicGlobal + Private interfaces must emit 1 Low finding"
    );
    assert_eq!(findings[0].severity, FindingSeverity::Low);
    assert_eq!(findings[0].target.target_key(), "host:test-host");
    assert_eq!(findings[0].discriminator, "MULTI_HOMED_PUB_PRIV:eth0:eth1");
    assert!(findings[0].description.contains("eth0"));
    assert!(findings[0].description.contains("eth1"));
}

#[test]
fn test_vector_15_net008_deterministic_fingerprint_reproducibility() {
    let mut engine = RuleEngine::new();
    engine.register_rule(Arc::new(Net008MultiHomedPublicPrivateRule::new()));

    let obs = make_topology_observation(
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

    let findings_run1 = engine.evaluate(&obs);
    let findings_run2 = engine.evaluate(&obs);

    assert_eq!(findings_run1.len(), 1);
    assert_eq!(findings_run2.len(), 1);
    assert_eq!(
        findings_run1[0].fingerprint, findings_run2[0].fingerprint,
        "Vector 15: Fingerprint must be bitwise reproducible across repeated evaluations"
    );
    assert_eq!(findings_run1[0].fingerprint.len(), 64);
}

#[test]
fn test_vector_16_privacy_zero_raw_mac_leakage() {
    let rule_net007 = Net007InvalidNeighborEntryRule::new();
    let obs_net007 = make_neighbor_observation(
        vec![NeighborRecord {
            ip_address: "224.0.0.1".to_string(),
            mac_address_hash: Some(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            state: NeighborState::Permanent,
            is_ipv6: false,
            ip_classification: IpClassification::Multicast,
            is_router: None,
        }],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings_007 = rule_net007.evaluate(&obs_net007);
    assert_eq!(findings_007.len(), 1);

    let evidence_str_007 = findings_007[0].raw_evidence.to_string();
    assert!(
        !evidence_str_007.contains("00:11:22") && !evidence_str_007.contains("AA:BB:CC"),
        "Vector 16: Zero raw MAC addresses permitted in NET-007 serialized evidence"
    );

    let rule_net008 = Net008MultiHomedPublicPrivateRule::new();
    let obs_net008 = make_topology_observation(
        vec![
            TopologyInterfaceNode {
                name: "eth0".to_string(),
                index: 2,
                is_up: true,
                is_loopback: false,
                ip_addresses: vec!["93.184.216.34".to_string()],
                mac_address_hash: Some("aabbccddeeff".to_string()),
            },
            TopologyInterfaceNode {
                name: "eth1".to_string(),
                index: 3,
                is_up: true,
                is_loopback: false,
                ip_addresses: vec!["192.168.1.100".to_string()],
                mac_address_hash: Some("112233445566".to_string()),
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

    let findings_008 = rule_net008.evaluate(&obs_net008);
    assert_eq!(findings_008.len(), 1);

    let evidence_str_008 = findings_008[0].raw_evidence.to_string();
    assert!(
        !evidence_str_008.contains("00:11:22") && !evidence_str_008.contains("AA:BB:CC"),
        "Vector 16: Zero raw MAC addresses permitted in NET-008 serialized evidence"
    );
}
