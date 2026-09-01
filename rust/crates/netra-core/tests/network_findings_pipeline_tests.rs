//! # NETRA Phase 8.7.5 — Network Findings Pipeline Integration Tests
//!
//! Validates canonical network finding evaluation, ScannerSupervisor scan cycle integration,
//! deterministic deduplication, automated failure-isolated reconciliation, reopen/suppress lifecycle,
//! Transaction A/B boundaries, and non-network baseline rule regression.

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
use netra_core::storage::repositories::findings::FindingsRepository;
use netra_core::storage::repositories::queue::ObservationQueueRepository;
use netra_core::storage::{DatabaseEngine, FindingStatus, ObservationStatus};

// ============================================================================
// MOCK SCANNERS
// ============================================================================

struct MockIfaceScanner {
    interfaces: Vec<InterfaceRecord>,
    privilege: PrivilegeStatus,
    should_fail: bool,
}

#[async_trait]
impl PostureScanner for MockIfaceScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.interfaces.v1"
    }
    fn domain(&self) -> ObservationType {
        ObservationType::Interfaces
    }
    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        if self.should_fail {
            return Err(netra_core::error::NetraError::platform(
                "Mock interface failure",
            ));
        }
        Observation::new(
            device_id.clone(),
            self.scanner_id(),
            self.domain(),
            TargetDescriptor::Host {
                hostname: "mock-host".to_string(),
            },
            5,
            self.privilege,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            SensitivityLevel::Confidential,
            ObservationPayload::Interfaces(InterfaceObservationPayload {
                interfaces: self.interfaces.clone(),
            }),
        )
    }
}

struct MockRouteScanner {
    routes: Vec<RouteRecord>,
    privilege: PrivilegeStatus,
    should_fail: bool,
}

#[async_trait]
impl PostureScanner for MockRouteScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.routes.v1"
    }
    fn domain(&self) -> ObservationType {
        ObservationType::Routes
    }
    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        if self.should_fail {
            return Err(netra_core::error::NetraError::platform(
                "Mock route failure",
            ));
        }
        Observation::new(
            device_id.clone(),
            self.scanner_id(),
            self.domain(),
            TargetDescriptor::Host {
                hostname: "mock-host".to_string(),
            },
            5,
            self.privilege,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            SensitivityLevel::Confidential,
            ObservationPayload::Routes(RouteObservationPayload {
                routes: self.routes.clone(),
                default_gateways: vec!["192.168.1.1".to_string()],
            }),
        )
    }
}

struct MockDnsScanner {
    dns_servers: Vec<DnsServerRecord>,
    privilege: PrivilegeStatus,
    should_fail: bool,
}

#[async_trait]
impl PostureScanner for MockDnsScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.dns.v1"
    }
    fn domain(&self) -> ObservationType {
        ObservationType::Dns
    }
    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        if self.should_fail {
            return Err(netra_core::error::NetraError::platform("Mock DNS failure"));
        }
        Observation::new(
            device_id.clone(),
            self.scanner_id(),
            self.domain(),
            TargetDescriptor::Host {
                hostname: "mock-host".to_string(),
            },
            5,
            self.privilege,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            SensitivityLevel::Confidential,
            ObservationPayload::Dns(DnsObservationPayload {
                dns_servers: self.dns_servers.clone(),
                search_domains: vec!["local".to_string()],
                is_dynamic_dns_enabled: Some(false),
            }),
        )
    }
}

struct MockNeighborScanner {
    neighbors: Vec<NeighborRecord>,
    privilege: PrivilegeStatus,
    should_fail: bool,
}

#[async_trait]
impl PostureScanner for MockNeighborScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.neighbors.v1"
    }
    fn domain(&self) -> ObservationType {
        ObservationType::Neighbors
    }
    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        if self.should_fail {
            return Err(netra_core::error::NetraError::platform(
                "Mock neighbor failure",
            ));
        }
        Observation::new(
            device_id.clone(),
            self.scanner_id(),
            self.domain(),
            TargetDescriptor::Host {
                hostname: "mock-host".to_string(),
            },
            5,
            self.privilege,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            SensitivityLevel::Confidential,
            ObservationPayload::Neighbors(NeighborObservationPayload {
                neighbors: self.neighbors.clone(),
            }),
        )
    }
}

struct MockSocketScanner {
    sockets: Vec<SocketRecord>,
}

#[async_trait]
impl PostureScanner for MockSocketScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.sockets.v1"
    }
    fn domain(&self) -> ObservationType {
        ObservationType::Sockets
    }
    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        Observation::new(
            device_id.clone(),
            self.scanner_id(),
            self.domain(),
            TargetDescriptor::Host {
                hostname: "mock-host".to_string(),
            },
            5,
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            SensitivityLevel::Public,
            ObservationPayload::Sockets(SocketObservationPayload {
                sockets: self.sockets.clone(),
            }),
        )
    }
}

struct MockFirewallScanner {
    profiles: Vec<FirewallProfileRecord>,
}

#[async_trait]
impl PostureScanner for MockFirewallScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.firewall.v1"
    }
    fn domain(&self) -> ObservationType {
        ObservationType::Firewall
    }
    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        Observation::new(
            device_id.clone(),
            self.scanner_id(),
            self.domain(),
            TargetDescriptor::Firewall {
                profile: "Public".to_string(),
            },
            5,
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            SensitivityLevel::Confidential,
            ObservationPayload::Firewall(FirewallObservationPayload {
                profiles: self.profiles.clone(),
            }),
        )
    }
}

// ============================================================================
// HELPER: BUILD FULL NETWORK ANOMALY COLLECTORS
// ============================================================================

fn create_full_anomaly_scanners() -> Vec<Arc<dyn PostureScanner>> {
    let ifaces = vec![
        InterfaceRecord {
            interface_name: "eth0".to_string(),
            friendly_name: Some("Ethernet 1".to_string()),
            interface_index: 2,
            mac_address_hash: Some("mock_mac_hash_1".to_string()),
            interface_type: InterfaceType::Ethernet,
            oper_status: InterfaceStatus::Up,
            ip_addresses: vec![
                IpNetworkRecord {
                    ip_address: "10.0.0.5".to_string(),
                    prefix_length: 24,
                    is_ipv6: false,
                    classification: IpClassification::Private,
                    broadcast_address: Some("10.0.0.255".to_string()),
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
            is_dhcp_enabled: Some(false),
            is_virtual: false,
        },
        InterfaceRecord {
            interface_name: "eth1".to_string(),
            friendly_name: Some("Ethernet 2".to_string()),
            interface_index: 3,
            mac_address_hash: Some("mock_mac_hash_2".to_string()),
            interface_type: InterfaceType::Ethernet,
            oper_status: InterfaceStatus::Up,
            ip_addresses: vec![IpNetworkRecord {
                ip_address: "192.168.1.50".to_string(),
                prefix_length: 24,
                is_ipv6: false,
                classification: IpClassification::Private,
                broadcast_address: Some("192.168.1.255".to_string()),
            }],
            mtu: 1500,
            is_loopback: false,
            is_point_to_point: false,
            is_dhcp_enabled: Some(false),
            is_virtual: false,
        },
    ];

    let routes = vec![
        // Default gateway 192.168.1.1 on eth0 (triggers NET-003 off-subnet, and competing default route NET-004)
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
        // Competing default route with equal metric 10 (triggers NET-004)
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
        // Loopback route pointing to non-loopback interface (triggers NET-006)
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
    ];

    let dns_servers = vec![
        // Unspecified 0.0.0.0 resolver (triggers NET-005)
        DnsServerRecord {
            server_address: "0.0.0.0".to_string(),
            interface_name: Some("eth0".to_string()),
            is_ipv6: false,
            classification: IpClassification::Unspecified,
        },
    ];

    let neighbors = vec![
        // Non-unicast broadcast neighbor (triggers NET-007)
        NeighborRecord {
            ip_address: "255.255.255.255".to_string(),
            mac_address_hash: None,
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            state: NeighborState::Reachable,
            is_ipv6: false,
            ip_classification: IpClassification::Broadcast,
            is_router: Some(false),
        },
    ];

    vec![
        Arc::new(MockIfaceScanner {
            interfaces: ifaces,
            privilege: PrivilegeStatus::Available,
            should_fail: false,
        }),
        Arc::new(MockRouteScanner {
            routes,
            privilege: PrivilegeStatus::Available,
            should_fail: false,
        }),
        Arc::new(MockDnsScanner {
            dns_servers,
            privilege: PrivilegeStatus::Available,
            should_fail: false,
        }),
        Arc::new(MockNeighborScanner {
            neighbors,
            privilege: PrivilegeStatus::Available,
            should_fail: false,
        }),
    ]
}

fn create_clean_network_scanners() -> Vec<Arc<dyn PostureScanner>> {
    let ifaces = vec![InterfaceRecord {
        interface_name: "eth0".to_string(),
        friendly_name: Some("Ethernet 1".to_string()),
        interface_index: 2,
        mac_address_hash: Some("mock_mac_hash_1".to_string()),
        interface_type: InterfaceType::Ethernet,
        oper_status: InterfaceStatus::Up,
        ip_addresses: vec![IpNetworkRecord {
            ip_address: "192.168.1.50".to_string(),
            prefix_length: 24,
            is_ipv6: false,
            classification: IpClassification::Private,
            broadcast_address: Some("192.168.1.255".to_string()),
        }],
        mtu: 1500,
        is_loopback: false,
        is_point_to_point: false,
        is_dhcp_enabled: Some(false),
        is_virtual: false,
    }];

    let routes = vec![
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
            destination_cidr: "127.0.0.0/8".to_string(),
            gateway_ip: None,
            interface_index: 1,
            interface_name: Some("lo".to_string()),
            metric: 1,
            is_ipv6: false,
            is_default_gateway: false,
            route_type: RouteType::Local,
        },
    ];

    let dns_servers = vec![DnsServerRecord {
        server_address: "1.1.1.1".to_string(),
        interface_name: Some("eth0".to_string()),
        is_ipv6: false,
        classification: IpClassification::PublicGlobal,
    }];

    let neighbors = vec![NeighborRecord {
        ip_address: "192.168.1.1".to_string(),
        mac_address_hash: None,
        interface_index: 2,
        interface_name: Some("eth0".to_string()),
        state: NeighborState::Reachable,
        is_ipv6: false,
        ip_classification: IpClassification::Private,
        is_router: Some(true),
    }];

    vec![
        Arc::new(MockIfaceScanner {
            interfaces: ifaces,
            privilege: PrivilegeStatus::Available,
            should_fail: false,
        }),
        Arc::new(MockRouteScanner {
            routes,
            privilege: PrivilegeStatus::Available,
            should_fail: false,
        }),
        Arc::new(MockDnsScanner {
            dns_servers,
            privilege: PrivilegeStatus::Available,
            should_fail: false,
        }),
        Arc::new(MockNeighborScanner {
            neighbors,
            privilege: PrivilegeStatus::Available,
            should_fail: false,
        }),
    ]
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[tokio::test]
async fn test_full_scan_cycle_generates_and_persists_all_six_network_findings() {
    let storage = Arc::new(DatabaseEngine::in_memory().unwrap());
    let scanners = create_full_anomaly_scanners();
    let supervisor = ScannerSupervisor::new(storage.clone(), scanners);

    let device_id = DeviceId::new();
    let res = supervisor.run_scan_cycle(&device_id).await.unwrap();

    assert_eq!(res.total_scanners, 4);
    assert_eq!(res.successful_scanners, 4);
    assert_eq!(res.observations_collected, 4);
    assert!(res.topology_synthesized);
    assert!(
        res.findings_evaluated >= 6,
        "All 6 network posture findings must be evaluated"
    );

    // Query SQLite local_findings
    let open_findings = storage
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .unwrap();

    let rule_ids: HashSet<String> = open_findings.iter().map(|f| f.rule_id.clone()).collect();

    assert!(rule_ids.contains("NET-003-GATEWAY-OFF-SUBNET"));
    assert!(rule_ids.contains("NET-004-COMPETING-DEFAULT-GATEWAYS"));
    assert!(rule_ids.contains("NET-005-INVALID-DNS-RESOLVER"));
    assert!(rule_ids.contains("NET-006-LOOPBACK-ROUTE-LEAK"));
    assert!(rule_ids.contains("NET-007-INVALID-NEIGHBOR-ENTRY"));
    assert!(rule_ids.contains("NET-008-MULTI-HOMED-PUBLIC-PRIVATE"));

    for f in &open_findings {
        assert_eq!(f.status, FindingStatus::Open);
        assert_eq!(f.occurrence_count, 1);
        assert!(!f.fingerprint.is_empty());
    }

    // Verify observation queue has 4 raw observations + 1 synthesized topology observation
    let queue_count = storage
        .with_reader(|conn| {
            ObservationQueueRepository::count_by_status(conn, ObservationStatus::Queued)
        })
        .await
        .unwrap();
    assert_eq!(queue_count, 5);
}

#[tokio::test]
async fn test_repeated_scan_deduplication_and_occurrence_increment() {
    let storage = Arc::new(DatabaseEngine::in_memory().unwrap());
    let scanners = create_full_anomaly_scanners();
    let supervisor = ScannerSupervisor::new(storage.clone(), scanners);
    let device_id = DeviceId::new();

    // Cycle 1
    supervisor.run_scan_cycle(&device_id).await.unwrap();
    let findings_c1 = storage
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .unwrap();

    // Cycle 2 (identical telemetry)
    supervisor.run_scan_cycle(&device_id).await.unwrap();
    let findings_c2 = storage
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .unwrap();

    assert_eq!(findings_c1.len(), findings_c2.len());

    let all_findings = storage
        .with_reader(FindingsRepository::list_all)
        .await
        .unwrap();
    assert_eq!(
        all_findings.len(),
        findings_c1.len(),
        "Zero duplicate rows in local_findings"
    );

    for f in &findings_c2 {
        assert_eq!(
            f.occurrence_count, 2,
            "Occurrence count must increment to 2 on repeat scan"
        );
        assert_eq!(f.status, FindingStatus::Open);
    }
}

#[tokio::test]
async fn test_automated_resolution_and_reopen_lifecycle() {
    let storage = Arc::new(DatabaseEngine::in_memory().unwrap());
    let device_id = DeviceId::new();

    // 1. Cycle 1: Anomalies present -> 6 findings OPEN
    let supervisor_dirty = ScannerSupervisor::new(storage.clone(), create_full_anomaly_scanners());
    let res1 = supervisor_dirty.run_scan_cycle(&device_id).await.unwrap();
    assert!(res1.active_open_findings >= 6);

    // 2. Cycle 2: Network is remediated / clean -> findings RESOLVED
    let supervisor_clean = ScannerSupervisor::new(storage.clone(), create_clean_network_scanners());
    let res2 = supervisor_clean.run_scan_cycle(&device_id).await.unwrap();
    assert_eq!(
        res2.active_open_findings, 0,
        "All remediated findings must transition to RESOLVED"
    );

    let resolved_findings = storage
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Resolved))
        .await
        .unwrap();
    assert!(
        resolved_findings.len() >= 6,
        "Findings must be marked RESOLVED in database"
    );

    // 3. Cycle 3: Anomaly re-introduced -> findings REOPENED to OPEN
    let res3 = supervisor_dirty.run_scan_cycle(&device_id).await.unwrap();
    assert!(res3.active_open_findings >= 6);

    let reopened_findings = storage
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .unwrap();
    for f in &reopened_findings {
        assert_eq!(f.status, FindingStatus::Open);
        assert_eq!(
            f.occurrence_count, 2,
            "Occurrence count must continue incrementing after reopen"
        );
    }
}

#[tokio::test]
async fn test_suppressed_finding_remains_suppressed_on_rescan() {
    let storage = Arc::new(DatabaseEngine::in_memory().unwrap());
    let supervisor = ScannerSupervisor::new(storage.clone(), create_full_anomaly_scanners());
    let device_id = DeviceId::new();

    // 1. Cycle 1: Generate findings
    supervisor.run_scan_cycle(&device_id).await.unwrap();

    let open_findings = storage
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .unwrap();
    let target_fp = open_findings[0].fingerprint.clone();
    let target_fp_clone = target_fp.clone();

    // 2. Suppress the finding
    storage
        .with_writer(move |conn| {
            FindingsRepository::suppress(conn, &target_fp)?;
            Ok(())
        })
        .await
        .unwrap();

    // 3. Cycle 2: Rescan with anomaly still present
    supervisor.run_scan_cycle(&device_id).await.unwrap();

    let f = storage
        .with_reader(move |conn| FindingsRepository::get(conn, &target_fp_clone))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        f.status,
        FindingStatus::Suppressed,
        "Suppressed finding must NOT be overwritten to OPEN"
    );
    assert_eq!(f.occurrence_count, 2);
}

#[tokio::test]
async fn test_scanner_failure_isolation_preserves_open_findings() {
    let storage = Arc::new(DatabaseEngine::in_memory().unwrap());
    let device_id = DeviceId::new();

    // 1. Cycle 1: Healthy scan produces NET-005 (DNS anomaly)
    let supervisor1 = ScannerSupervisor::new(storage.clone(), create_full_anomaly_scanners());
    supervisor1.run_scan_cycle(&device_id).await.unwrap();

    let dns_findings = storage
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .unwrap()
        .into_iter()
        .filter(|f| f.rule_id == "NET-005-INVALID-DNS-RESOLVER")
        .collect::<Vec<_>>();
    assert_eq!(dns_findings.len(), 1);
    let dns_fp = dns_findings[0].fingerprint.clone();

    // 2. Cycle 2: DNS scanner fails (simulating network collector timeout/crash)
    let failing_scanners: Vec<Arc<dyn PostureScanner>> = vec![
        Arc::new(MockIfaceScanner {
            interfaces: vec![],
            privilege: PrivilegeStatus::Available,
            should_fail: false,
        }),
        Arc::new(MockRouteScanner {
            routes: vec![],
            privilege: PrivilegeStatus::Available,
            should_fail: false,
        }),
        Arc::new(MockDnsScanner {
            dns_servers: vec![],
            privilege: PrivilegeStatus::Available,
            should_fail: true, // Failed collector
        }),
        Arc::new(MockNeighborScanner {
            neighbors: vec![],
            privilege: PrivilegeStatus::Available,
            should_fail: false,
        }),
    ];

    let supervisor2 = ScannerSupervisor::new(storage.clone(), failing_scanners);
    let res2 = supervisor2.run_scan_cycle(&device_id).await.unwrap();

    // Scanner failed: total 4, successful 3
    assert_eq!(res2.total_scanners, 4);
    assert_eq!(res2.successful_scanners, 3);

    // CRITICAL: DNS finding must NOT be resolved due to missing telemetry
    let f = storage
        .with_reader(move |conn| FindingsRepository::get(conn, &dns_fp))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        f.status,
        FindingStatus::Open,
        "Failed scanner telemetry MUST NOT falsely resolve existing findings"
    );
}

#[tokio::test]
async fn test_missing_topology_sources_preserves_topology_findings() {
    let storage = Arc::new(DatabaseEngine::in_memory().unwrap());
    let device_id = DeviceId::new();

    // 1. Cycle 1: Generate NET-003
    let supervisor1 = ScannerSupervisor::new(storage.clone(), create_full_anomaly_scanners());
    supervisor1.run_scan_cycle(&device_id).await.unwrap();

    let topo_findings = storage
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .unwrap()
        .into_iter()
        .filter(|f| f.rule_id == "NET-003-GATEWAY-OFF-SUBNET")
        .collect::<Vec<_>>();
    assert_eq!(topo_findings.len(), 1);
    let topo_fp = topo_findings[0].fingerprint.clone();

    // 2. Cycle 2: Route scanner fails -> route is in missing_sources -> NET-003 suppressed by guardrail
    let degraded_scanners: Vec<Arc<dyn PostureScanner>> = vec![
        Arc::new(MockIfaceScanner {
            interfaces: vec![],
            privilege: PrivilegeStatus::Available,
            should_fail: false,
        }),
        Arc::new(MockRouteScanner {
            routes: vec![],
            privilege: PrivilegeStatus::Available,
            should_fail: true, // Missing required source for NET-003
        }),
        Arc::new(MockDnsScanner {
            dns_servers: vec![],
            privilege: PrivilegeStatus::Available,
            should_fail: false,
        }),
        Arc::new(MockNeighborScanner {
            neighbors: vec![],
            privilege: PrivilegeStatus::Available,
            should_fail: false,
        }),
    ];

    let supervisor2 = ScannerSupervisor::new(storage.clone(), degraded_scanners);
    supervisor2.run_scan_cycle(&device_id).await.unwrap();

    let f = storage
        .with_reader(move |conn| FindingsRepository::get(conn, &topo_fp))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        f.status,
        FindingStatus::Open,
        "Missing required topology source must NOT resolve previous finding"
    );
}

#[tokio::test]
async fn test_fingerprint_distinctness_and_no_discriminator_aliasing() {
    let storage = Arc::new(DatabaseEngine::in_memory().unwrap());
    let device_id = DeviceId::new();

    // 2 distinct invalid DNS resolvers on same host
    let dns_servers = vec![
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
    ];

    let scanners: Vec<Arc<dyn PostureScanner>> = vec![Arc::new(MockDnsScanner {
        dns_servers,
        privilege: PrivilegeStatus::Available,
        should_fail: false,
    })];

    let supervisor = ScannerSupervisor::new(storage.clone(), scanners);
    supervisor.run_scan_cycle(&device_id).await.unwrap();

    let open_findings = storage
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .unwrap();

    assert_eq!(
        open_findings.len(),
        2,
        "Must persist 2 distinct findings with different discriminators without aliasing"
    );
    assert_ne!(open_findings[0].fingerprint, open_findings[1].fingerprint);
}

#[tokio::test]
async fn test_non_network_rules_regression_alongside_network_rules() {
    let storage = Arc::new(DatabaseEngine::in_memory().unwrap());
    let device_id = DeviceId::new();

    let mut scanners = create_full_anomaly_scanners();

    // Add baseline mock scanners
    scanners.push(Arc::new(MockSocketScanner {
        sockets: vec![SocketRecord {
            protocol: SocketProtocol::Tcp,
            local_address: "0.0.0.0".to_string(),
            local_port: 23, // Plaintext Telnet -> triggers NET-001
            remote_address: None,
            remote_port: None,
            state: "LISTEN".to_string(),
            owning_pid: 1234,
            process_name: Some("telnetd".to_string()),
        }],
    }));

    scanners.push(Arc::new(MockFirewallScanner {
        profiles: vec![FirewallProfileRecord {
            profile_name: "Public".to_string(),
            is_enabled: false, // Disabled firewall -> triggers FW-001
            default_inbound_action: "ALLOW".to_string(),
            default_outbound_action: "ALLOW".to_string(),
            active_rules_count: 0,
        }],
    }));

    let supervisor = ScannerSupervisor::new(storage.clone(), scanners);
    let res = supervisor.run_scan_cycle(&device_id).await.unwrap();

    assert_eq!(res.total_scanners, 6);
    assert_eq!(res.successful_scanners, 6);
    assert!(res.findings_evaluated >= 8);

    let open_findings = storage
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .unwrap();

    let rule_ids: HashSet<String> = open_findings.iter().map(|f| f.rule_id.clone()).collect();

    // Verify baseline rules
    assert!(rule_ids.contains("NET-001-PLAINTEXT-PORT"));
    assert!(rule_ids.contains("FW-001-PROFILE-DISABLED"));

    // Verify network rules
    assert!(rule_ids.contains("NET-003-GATEWAY-OFF-SUBNET"));
    assert!(rule_ids.contains("NET-004-COMPETING-DEFAULT-GATEWAYS"));
    assert!(rule_ids.contains("NET-005-INVALID-DNS-RESOLVER"));
    assert!(rule_ids.contains("NET-006-LOOPBACK-ROUTE-LEAK"));
    assert!(rule_ids.contains("NET-007-INVALID-NEIGHBOR-ENTRY"));
    assert!(rule_ids.contains("NET-008-MULTI-HOMED-PUBLIC-PRIVATE"));
}

#[tokio::test]
async fn test_single_domain_scan_reconciliation_and_execution() {
    let storage = Arc::new(DatabaseEngine::in_memory().unwrap());
    let device_id = DeviceId::new();

    let dirty_dns = Arc::new(MockDnsScanner {
        dns_servers: vec![DnsServerRecord {
            server_address: "0.0.0.0".to_string(),
            interface_name: Some("eth0".to_string()),
            is_ipv6: false,
            classification: IpClassification::Unspecified,
        }],
        privilege: PrivilegeStatus::Available,
        should_fail: false,
    });

    let supervisor = ScannerSupervisor::new(storage.clone(), vec![dirty_dns]);
    let res = supervisor
        .run_single_domain_scan(ObservationType::Dns, &device_id)
        .await
        .unwrap();

    assert_eq!(res.findings_evaluated, 1);
    assert_eq!(res.active_open_findings, 1);

    // Clean DNS scan
    let clean_dns = Arc::new(MockDnsScanner {
        dns_servers: vec![DnsServerRecord {
            server_address: "8.8.8.8".to_string(),
            interface_name: Some("eth0".to_string()),
            is_ipv6: false,
            classification: IpClassification::PublicGlobal,
        }],
        privilege: PrivilegeStatus::Available,
        should_fail: false,
    });

    let supervisor_clean = ScannerSupervisor::new(storage.clone(), vec![clean_dns]);
    let res_clean = supervisor_clean
        .run_single_domain_scan(ObservationType::Dns, &device_id)
        .await
        .unwrap();

    assert_eq!(res_clean.findings_evaluated, 0);
    assert_eq!(res_clean.active_open_findings, 0);

    let resolved = storage
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Resolved))
        .await
        .unwrap();
    assert_eq!(resolved.len(), 1);
}
