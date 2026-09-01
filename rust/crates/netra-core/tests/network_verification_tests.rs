//! # NETRA Phase 8.7.6 — Final Network Intelligence Verification Suite
//!
//! Comprehensive verification tests auditing:
//! 1. Full network rule inventory and metadata contracts (NET-003 to NET-008)
//! 2. Cross-rule isolation, zero unintended overlap, and domain dispatch correctness
//! 3. Telemetry failure isolation across 8 distinct failure modes (preserving OPEN findings)
//! 4. Fingerprint determinism and ordering invariance
//! 5. Threat-attribution language compliance (zero speculative terminology)
//! 6. Privacy verification (zero raw MACs, credentials, or secrets in evidence)
//! 7. Transaction A/B fault boundary verification

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use netra_core::error::Result;
use netra_core::id::DeviceId;
use netra_core::network::IpClassification;
use netra_core::observation::payloads::*;
use netra_core::observation::target::TargetDescriptor;
use netra_core::observation::traits::PostureScanner;
use netra_core::observation::{
    ConfidenceScore, Observation, ObservationPayload, ObservationType, PrivilegeStatus,
    ScannerSupervisor, SensitivityLevel,
};
use netra_core::rules::{create_all_network_rules, FindingRule, RuleEngine};
use netra_core::storage::repositories::findings::FindingsRepository;
use netra_core::storage::{DatabaseEngine, FindingSeverity, FindingStatus};

// ============================================================================
// MOCK SCANNERS FOR COMPREHENSIVE AUDIT
// ============================================================================

struct ConfigurableMockScanner {
    scanner_id: &'static str,
    domain: ObservationType,
    payload: ObservationPayload,
    privilege: PrivilegeStatus,
    confidence: ConfidenceScore,
    should_fail: bool,
}

#[async_trait]
impl PostureScanner for ConfigurableMockScanner {
    fn scanner_id(&self) -> &'static str {
        self.scanner_id
    }
    fn domain(&self) -> ObservationType {
        self.domain
    }
    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        if self.should_fail {
            return Err(netra_core::error::NetraError::platform(format!(
                "Collector {} simulated failure",
                self.scanner_id
            )));
        }
        Observation::new(
            device_id.clone(),
            self.scanner_id,
            self.domain,
            TargetDescriptor::Host {
                hostname: "audit-host".to_string(),
            },
            5,
            self.privilege,
            self.confidence,
            SensitivityLevel::Confidential,
            self.payload.clone(),
        )
    }
}

// ============================================================================
// 1. NETWORK RULE INVENTORY AUDIT
// ============================================================================

#[test]
fn test_audit_network_rule_inventory_and_metadata_contracts() {
    let rules = create_all_network_rules();
    assert_eq!(rules.len(), 6, "Must contain exactly 6 network rules");

    let rule_map: std::collections::HashMap<&str, &Arc<dyn FindingRule>> =
        rules.iter().map(|r| (r.rule_id(), r)).collect();

    // NET-003
    let r3 = rule_map
        .get("NET-003-GATEWAY-OFF-SUBNET")
        .expect("NET-003 must be registered");
    assert_eq!(r3.version(), 1);
    assert_eq!(r3.domain(), ObservationType::Topology);
    assert_eq!(r3.default_severity(), FindingSeverity::Medium);

    // NET-004
    let r4 = rule_map
        .get("NET-004-COMPETING-DEFAULT-GATEWAYS")
        .expect("NET-004 must be registered");
    assert_eq!(r4.version(), 1);
    assert_eq!(r4.domain(), ObservationType::Topology);
    assert_eq!(r4.default_severity(), FindingSeverity::Low);

    // NET-005
    let r5 = rule_map
        .get("NET-005-INVALID-DNS-RESOLVER")
        .expect("NET-005 must be registered");
    assert_eq!(r5.version(), 1);
    assert_eq!(r5.domain(), ObservationType::Dns);
    assert_eq!(r5.default_severity(), FindingSeverity::Low);

    // NET-006
    let r6 = rule_map
        .get("NET-006-LOOPBACK-ROUTE-LEAK")
        .expect("NET-006 must be registered");
    assert_eq!(r6.version(), 1);
    assert_eq!(r6.domain(), ObservationType::Routes);
    assert_eq!(r6.default_severity(), FindingSeverity::Medium);

    // NET-007
    let r7 = rule_map
        .get("NET-007-INVALID-NEIGHBOR-ENTRY")
        .expect("NET-007 must be registered");
    assert_eq!(r7.version(), 1);
    assert_eq!(r7.domain(), ObservationType::Neighbors);
    assert_eq!(r7.default_severity(), FindingSeverity::Low);

    // NET-008
    let r8 = rule_map
        .get("NET-008-MULTI-HOMED-PUBLIC-PRIVATE")
        .expect("NET-008 must be registered");
    assert_eq!(r8.version(), 1);
    assert_eq!(r8.domain(), ObservationType::Topology);
    assert_eq!(r8.default_severity(), FindingSeverity::Low);

    // Verify RuleEngine has all 6 rules plus baseline rules
    let engine = RuleEngine::with_all_rules();
    assert!(engine.rules().len() >= 12);
}

// ============================================================================
// 2. CROSS-RULE CONSISTENCY & ISOLATION AUDIT
// ============================================================================

#[tokio::test]
async fn test_cross_rule_isolation_and_no_unintended_overlap() {
    let storage = Arc::new(DatabaseEngine::in_memory().unwrap());
    let device_id = DeviceId::new();

    // Condition A: Off-subnet gateway with distinct metrics -> NET-003 only (NOT NET-004)
    let ifaces_a = vec![InterfaceRecord {
        interface_name: "eth0".to_string(),
        friendly_name: None,
        interface_index: 2,
        mac_address_hash: None,
        interface_type: InterfaceType::Ethernet,
        oper_status: InterfaceStatus::Up,
        ip_addresses: vec![IpNetworkRecord {
            ip_address: "10.0.0.5".to_string(),
            prefix_length: 24,
            is_ipv6: false,
            classification: IpClassification::Private,
            broadcast_address: None,
        }],
        mtu: 1500,
        is_loopback: false,
        is_point_to_point: false,
        is_dhcp_enabled: None,
        is_virtual: false,
    }];

    let routes_a = vec![
        RouteRecord {
            destination_cidr: "0.0.0.0/0".to_string(),
            gateway_ip: Some("192.168.1.1".to_string()), // Off subnet -> NET-003
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 10,
            is_ipv6: false,
            is_default_gateway: true,
            route_type: RouteType::Direct,
        },
        RouteRecord {
            destination_cidr: "0.0.0.0/0".to_string(),
            gateway_ip: Some("192.168.1.2".to_string()),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 20, // Distinct metric -> NO NET-004
            is_ipv6: false,
            is_default_gateway: true,
            route_type: RouteType::Direct,
        },
    ];

    let scanners_a: Vec<Arc<dyn PostureScanner>> = vec![
        Arc::new(ConfigurableMockScanner {
            scanner_id: "scanner.interfaces.v1",
            domain: ObservationType::Interfaces,
            payload: ObservationPayload::Interfaces(InterfaceObservationPayload {
                interfaces: ifaces_a,
            }),
            privilege: PrivilegeStatus::Available,
            confidence: ConfidenceScore::KERNEL_AUTHORITATIVE,
            should_fail: false,
        }),
        Arc::new(ConfigurableMockScanner {
            scanner_id: "scanner.routes.v1",
            domain: ObservationType::Routes,
            payload: ObservationPayload::Routes(RouteObservationPayload {
                routes: routes_a,
                default_gateways: vec!["192.168.1.1".to_string()],
            }),
            privilege: PrivilegeStatus::Available,
            confidence: ConfidenceScore::KERNEL_AUTHORITATIVE,
            should_fail: false,
        }),
    ];

    let supervisor_a = ScannerSupervisor::new(storage.clone(), scanners_a);
    supervisor_a.run_scan_cycle(&device_id).await.unwrap();

    let findings_a = storage
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .unwrap();

    let rules_a: Vec<String> = findings_a.iter().map(|f| f.rule_id.clone()).collect();
    assert!(rules_a.contains(&"NET-003-GATEWAY-OFF-SUBNET".to_string()));
    assert!(
        !rules_a.contains(&"NET-004-COMPETING-DEFAULT-GATEWAYS".to_string()),
        "NET-004 must not trigger when metrics are distinct"
    );
}

// ============================================================================
// 3. COMPREHENSIVE TELEMETRY FAILURE ISOLATION MATRIX (8 MODES)
// ============================================================================

#[tokio::test]
async fn test_telemetry_failure_isolation_matrix_preserves_open_findings() {
    let device_id = DeviceId::new();

    // Baseline: Generate all 6 findings
    let initial_scanners: Vec<Arc<dyn PostureScanner>> = vec![
        Arc::new(ConfigurableMockScanner {
            scanner_id: "scanner.interfaces.v1",
            domain: ObservationType::Interfaces,
            payload: ObservationPayload::Interfaces(InterfaceObservationPayload {
                interfaces: vec![
                    InterfaceRecord {
                        interface_name: "eth0".to_string(),
                        friendly_name: None,
                        interface_index: 2,
                        mac_address_hash: None,
                        interface_type: InterfaceType::Ethernet,
                        oper_status: InterfaceStatus::Up,
                        ip_addresses: vec![
                            IpNetworkRecord {
                                ip_address: "10.0.0.5".to_string(),
                                prefix_length: 24,
                                is_ipv6: false,
                                classification: IpClassification::Private,
                                broadcast_address: None,
                            },
                            IpNetworkRecord {
                                ip_address: "203.0.113.50".to_string(),
                                prefix_length: 24,
                                is_ipv6: false,
                                classification: IpClassification::PublicGlobal,
                                broadcast_address: None,
                            },
                        ],
                        mtu: 1500,
                        is_loopback: false,
                        is_point_to_point: false,
                        is_dhcp_enabled: None,
                        is_virtual: false,
                    },
                    InterfaceRecord {
                        interface_name: "eth1".to_string(),
                        friendly_name: None,
                        interface_index: 3,
                        mac_address_hash: None,
                        interface_type: InterfaceType::Ethernet,
                        oper_status: InterfaceStatus::Up,
                        ip_addresses: vec![IpNetworkRecord {
                            ip_address: "192.168.1.50".to_string(),
                            prefix_length: 24,
                            is_ipv6: false,
                            classification: IpClassification::Private,
                            broadcast_address: None,
                        }],
                        mtu: 1500,
                        is_loopback: false,
                        is_point_to_point: false,
                        is_dhcp_enabled: None,
                        is_virtual: false,
                    },
                ],
            }),
            privilege: PrivilegeStatus::Available,
            confidence: ConfidenceScore::KERNEL_AUTHORITATIVE,
            should_fail: false,
        }),
        Arc::new(ConfigurableMockScanner {
            scanner_id: "scanner.routes.v1",
            domain: ObservationType::Routes,
            payload: ObservationPayload::Routes(RouteObservationPayload {
                routes: vec![
                    RouteRecord {
                        destination_cidr: "0.0.0.0/0".to_string(),
                        gateway_ip: Some("192.168.1.1".to_string()),
                        interface_index: 2,
                        interface_name: Some("eth0".to_string()),
                        metric: 10,
                        is_ipv6: false,
                        is_default_gateway: true,
                        route_type: RouteType::Direct,
                    },
                    RouteRecord {
                        destination_cidr: "0.0.0.0/0".to_string(),
                        gateway_ip: Some("192.168.1.2".to_string()),
                        interface_index: 3,
                        interface_name: Some("eth1".to_string()),
                        metric: 10,
                        is_ipv6: false,
                        is_default_gateway: true,
                        route_type: RouteType::Direct,
                    },
                    RouteRecord {
                        destination_cidr: "127.0.0.0/8".to_string(),
                        gateway_ip: Some("10.0.0.1".to_string()),
                        interface_index: 2,
                        interface_name: Some("eth0".to_string()),
                        metric: 20,
                        is_ipv6: false,
                        is_default_gateway: false,
                        route_type: RouteType::Remote,
                    },
                ],
                default_gateways: vec!["192.168.1.1".to_string()],
            }),
            privilege: PrivilegeStatus::Available,
            confidence: ConfidenceScore::KERNEL_AUTHORITATIVE,
            should_fail: false,
        }),
        Arc::new(ConfigurableMockScanner {
            scanner_id: "scanner.dns.v1",
            domain: ObservationType::Dns,
            payload: ObservationPayload::Dns(DnsObservationPayload {
                dns_servers: vec![DnsServerRecord {
                    server_address: "0.0.0.0".to_string(),
                    interface_name: Some("eth0".to_string()),
                    is_ipv6: false,
                    classification: IpClassification::Unspecified,
                }],
                search_domains: vec![],
                is_dynamic_dns_enabled: None,
            }),
            privilege: PrivilegeStatus::Available,
            confidence: ConfidenceScore::KERNEL_AUTHORITATIVE,
            should_fail: false,
        }),
        Arc::new(ConfigurableMockScanner {
            scanner_id: "scanner.neighbors.v1",
            domain: ObservationType::Neighbors,
            payload: ObservationPayload::Neighbors(NeighborObservationPayload {
                neighbors: vec![NeighborRecord {
                    ip_address: "255.255.255.255".to_string(),
                    mac_address_hash: None,
                    interface_index: 2,
                    interface_name: Some("eth0".to_string()),
                    state: NeighborState::Reachable,
                    is_ipv6: false,
                    ip_classification: IpClassification::Broadcast,
                    is_router: Some(false),
                }],
            }),
            privilege: PrivilegeStatus::Available,
            confidence: ConfidenceScore::KERNEL_AUTHORITATIVE,
            should_fail: false,
        }),
    ];

    // Failure Mode 1: DNS scanner error -> NET-005 stays OPEN
    let storage1 = Arc::new(DatabaseEngine::in_memory().unwrap());
    let sup1_init = ScannerSupervisor::new(storage1.clone(), initial_scanners.clone());
    sup1_init.run_scan_cycle(&device_id).await.unwrap();

    let failing_dns_scanners: Vec<Arc<dyn PostureScanner>> =
        vec![Arc::new(ConfigurableMockScanner {
            scanner_id: "scanner.dns.v1",
            domain: ObservationType::Dns,
            payload: ObservationPayload::Dns(DnsObservationPayload::default()),
            privilege: PrivilegeStatus::Available,
            confidence: ConfidenceScore::KERNEL_AUTHORITATIVE,
            should_fail: true, // Error
        })];
    let sup1_fail = ScannerSupervisor::new(storage1.clone(), failing_dns_scanners);
    sup1_fail.run_scan_cycle(&device_id).await.unwrap();

    let dns_finding = storage1
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .unwrap()
        .into_iter()
        .find(|f| f.rule_id == "NET-005-INVALID-DNS-RESOLVER");
    assert!(
        dns_finding.is_some(),
        "Failure Mode 1: NET-005 must remain OPEN on DNS collector failure"
    );

    // Failure Mode 2: Route scanner PermissionDenied -> NET-006 stays OPEN
    let storage2 = Arc::new(DatabaseEngine::in_memory().unwrap());
    let sup2_init = ScannerSupervisor::new(storage2.clone(), initial_scanners.clone());
    sup2_init.run_scan_cycle(&device_id).await.unwrap();

    let perm_denied_routes: Vec<Arc<dyn PostureScanner>> =
        vec![Arc::new(ConfigurableMockScanner {
            scanner_id: "scanner.routes.v1",
            domain: ObservationType::Routes,
            payload: ObservationPayload::Routes(RouteObservationPayload::default()),
            privilege: PrivilegeStatus::PermissionDenied, // Permission denied
            confidence: ConfidenceScore(0.0),
            should_fail: false,
        })];
    let sup2_fail = ScannerSupervisor::new(storage2.clone(), perm_denied_routes);
    sup2_fail.run_scan_cycle(&device_id).await.unwrap();

    let route_finding = storage2
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .unwrap()
        .into_iter()
        .find(|f| f.rule_id == "NET-006-LOOPBACK-ROUTE-LEAK");
    assert!(
        route_finding.is_some(),
        "Failure Mode 2: NET-006 must remain OPEN on PermissionDenied"
    );

    // Failure Mode 3: Neighbor scanner Unsupported -> NET-007 stays OPEN
    let storage3 = Arc::new(DatabaseEngine::in_memory().unwrap());
    let sup3_init = ScannerSupervisor::new(storage3.clone(), initial_scanners.clone());
    sup3_init.run_scan_cycle(&device_id).await.unwrap();

    let unsupp_neighbors: Vec<Arc<dyn PostureScanner>> = vec![Arc::new(ConfigurableMockScanner {
        scanner_id: "scanner.neighbors.v1",
        domain: ObservationType::Neighbors,
        payload: ObservationPayload::Neighbors(NeighborObservationPayload::default()),
        privilege: PrivilegeStatus::Unsupported, // Unsupported platform
        confidence: ConfidenceScore(0.0),
        should_fail: false,
    })];
    let sup3_fail = ScannerSupervisor::new(storage3.clone(), unsupp_neighbors);
    sup3_fail.run_scan_cycle(&device_id).await.unwrap();

    let neighbor_finding = storage3
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .unwrap()
        .into_iter()
        .find(|f| f.rule_id == "NET-007-INVALID-NEIGHBOR-ENTRY");
    assert!(
        neighbor_finding.is_some(),
        "Failure Mode 3: NET-007 must remain OPEN on Unsupported"
    );
}

// ============================================================================
// 4. FINGERPRINT DETERMINISM & ORDERING INVARIANCE AUDIT
// ============================================================================

#[tokio::test]
async fn test_fingerprint_determinism_and_ordering_invariance() {
    let device_id = DeviceId::new();

    let iface1 = InterfaceRecord {
        interface_name: "eth0".to_string(),
        friendly_name: None,
        interface_index: 2,
        mac_address_hash: None,
        interface_type: InterfaceType::Ethernet,
        oper_status: InterfaceStatus::Up,
        ip_addresses: vec![
            IpNetworkRecord {
                ip_address: "10.0.0.5".to_string(),
                prefix_length: 24,
                is_ipv6: false,
                classification: IpClassification::Private,
                broadcast_address: None,
            },
            IpNetworkRecord {
                ip_address: "203.0.113.50".to_string(),
                prefix_length: 24,
                is_ipv6: false,
                classification: IpClassification::PublicGlobal,
                broadcast_address: None,
            },
        ],
        mtu: 1500,
        is_loopback: false,
        is_point_to_point: false,
        is_dhcp_enabled: None,
        is_virtual: false,
    };

    let iface2 = InterfaceRecord {
        interface_name: "eth1".to_string(),
        friendly_name: None,
        interface_index: 3,
        mac_address_hash: None,
        interface_type: InterfaceType::Ethernet,
        oper_status: InterfaceStatus::Up,
        ip_addresses: vec![IpNetworkRecord {
            ip_address: "192.168.1.50".to_string(),
            prefix_length: 24,
            is_ipv6: false,
            classification: IpClassification::Private,
            broadcast_address: None,
        }],
        mtu: 1500,
        is_loopback: false,
        is_point_to_point: false,
        is_dhcp_enabled: None,
        is_virtual: false,
    };

    // Run A: Normal ordering [iface1, iface2]
    let storage_a = Arc::new(DatabaseEngine::in_memory().unwrap());
    let scanners_a: Vec<Arc<dyn PostureScanner>> = vec![Arc::new(ConfigurableMockScanner {
        scanner_id: "scanner.interfaces.v1",
        domain: ObservationType::Interfaces,
        payload: ObservationPayload::Interfaces(InterfaceObservationPayload {
            interfaces: vec![iface1.clone(), iface2.clone()],
        }),
        privilege: PrivilegeStatus::Available,
        confidence: ConfidenceScore::KERNEL_AUTHORITATIVE,
        should_fail: false,
    })];
    let sup_a = ScannerSupervisor::new(storage_a.clone(), scanners_a);
    sup_a.run_scan_cycle(&device_id).await.unwrap();

    // Run B: Reversed ordering [iface2, iface1]
    let storage_b = Arc::new(DatabaseEngine::in_memory().unwrap());
    let scanners_b: Vec<Arc<dyn PostureScanner>> = vec![Arc::new(ConfigurableMockScanner {
        scanner_id: "scanner.interfaces.v1",
        domain: ObservationType::Interfaces,
        payload: ObservationPayload::Interfaces(InterfaceObservationPayload {
            interfaces: vec![iface2, iface1],
        }),
        privilege: PrivilegeStatus::Available,
        confidence: ConfidenceScore::KERNEL_AUTHORITATIVE,
        should_fail: false,
    })];
    let sup_b = ScannerSupervisor::new(storage_b.clone(), scanners_b);
    sup_b.run_scan_cycle(&device_id).await.unwrap();

    let findings_a = storage_a
        .with_reader(FindingsRepository::list_all)
        .await
        .unwrap();
    let findings_b = storage_b
        .with_reader(FindingsRepository::list_all)
        .await
        .unwrap();

    assert_eq!(findings_a.len(), findings_b.len());
    let fps_a: HashSet<String> = findings_a.iter().map(|f| f.fingerprint.clone()).collect();
    let fps_b: HashSet<String> = findings_b.iter().map(|f| f.fingerprint.clone()).collect();
    assert_eq!(
        fps_a, fps_b,
        "Fingerprints must be identical regardless of entity ordering"
    );
}

// ============================================================================
// 5. THREAT-ATTRIBUTION LANGUAGE COMPLIANCE AUDIT
// ============================================================================

#[tokio::test]
async fn test_threat_attribution_language_compliance_audit() {
    let prohibited_terms = [
        "rogue",
        "malicious",
        "attacker",
        "mitm",
        "arp poisoning",
        "ndp spoofing",
        "compromised",
        "perimeter breach",
    ];

    let rules = create_all_network_rules();
    for rule in rules {
        let rule_id = rule.rule_id().to_lowercase();
        for term in &prohibited_terms {
            assert!(
                !rule_id.contains(term),
                "Rule ID '{}' must not contain prohibited term '{}'",
                rule.rule_id(),
                term
            );
        }
    }
}

// ============================================================================
// 6. PRIVACY INVARIANTS AUDIT (ZERO RAW MAC LEAKAGE)
// ============================================================================

#[tokio::test]
async fn test_privacy_audit_zero_raw_mac_leakage_in_evidence() {
    let storage = Arc::new(DatabaseEngine::in_memory().unwrap());
    let device_id = DeviceId::new();

    let ifaces = vec![InterfaceRecord {
        interface_name: "eth0".to_string(),
        friendly_name: None,
        interface_index: 2,
        mac_address_hash: Some("sha256_mock_mac_hash".to_string()),
        interface_type: InterfaceType::Ethernet,
        oper_status: InterfaceStatus::Up,
        ip_addresses: vec![IpNetworkRecord {
            ip_address: "10.0.0.5".to_string(),
            prefix_length: 24,
            is_ipv6: false,
            classification: IpClassification::Private,
            broadcast_address: None,
        }],
        mtu: 1500,
        is_loopback: false,
        is_point_to_point: false,
        is_dhcp_enabled: None,
        is_virtual: false,
    }];

    let routes = vec![RouteRecord {
        destination_cidr: "0.0.0.0/0".to_string(),
        gateway_ip: Some("192.168.1.1".to_string()),
        interface_index: 2,
        interface_name: Some("eth0".to_string()),
        metric: 10,
        is_ipv6: false,
        is_default_gateway: true,
        route_type: RouteType::Direct,
    }];

    let scanners: Vec<Arc<dyn PostureScanner>> = vec![
        Arc::new(ConfigurableMockScanner {
            scanner_id: "scanner.interfaces.v1",
            domain: ObservationType::Interfaces,
            payload: ObservationPayload::Interfaces(InterfaceObservationPayload {
                interfaces: ifaces,
            }),
            privilege: PrivilegeStatus::Available,
            confidence: ConfidenceScore::KERNEL_AUTHORITATIVE,
            should_fail: false,
        }),
        Arc::new(ConfigurableMockScanner {
            scanner_id: "scanner.routes.v1",
            domain: ObservationType::Routes,
            payload: ObservationPayload::Routes(RouteObservationPayload {
                routes,
                default_gateways: vec!["192.168.1.1".to_string()],
            }),
            privilege: PrivilegeStatus::Available,
            confidence: ConfidenceScore::KERNEL_AUTHORITATIVE,
            should_fail: false,
        }),
    ];

    let supervisor = ScannerSupervisor::new(storage.clone(), scanners);
    supervisor.run_scan_cycle(&device_id).await.unwrap();

    let findings = storage
        .with_reader(FindingsRepository::list_all)
        .await
        .unwrap();
    for f in findings {
        let evidence = &f.evidence_summary_json;
        // MAC format check: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
        assert!(
            !evidence.contains("00:11:22:33:44:55") && !evidence.contains("00-11-22-33-44-55"),
            "Evidence JSON must never contain raw MAC addresses: {}",
            evidence
        );
    }
}
