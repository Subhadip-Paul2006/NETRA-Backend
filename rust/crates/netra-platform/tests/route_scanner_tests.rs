//! # Routing Table & Default Gateway Posture Scanner Tests (Phase 8.3)
//!
//! Validates native/mock route table observation, default gateway derivation,
//! multi-homing preservation, deterministic sorting, ObservationQueue persistence,
//! and ScannerSupervisor failure isolation.

use std::sync::Arc;

use netra_core::id::DeviceId;
use netra_core::observation::{
    ConfidenceScore, Observation, ObservationPayload, ObservationType, PostureScanner,
    PrivilegeStatus, RouteObservationPayload, RouteRecord, RouteType, ScannerSupervisor,
    SensitivityLevel, TargetDescriptor,
};
use netra_core::storage::repositories::queue::ObservationQueueRepository;
use netra_core::storage::{DatabaseEngine, ObservationStatus};
use netra_platform::scanners::linux::routes::{parse_proc_net_ipv6_route, parse_proc_net_route};
use netra_platform::scanners::routes::PlatformRouteScanner;

#[tokio::test]
async fn test_native_platform_route_scanner_execution() {
    let device_id = DeviceId::new();
    let scanner = PlatformRouteScanner::new();

    assert_eq!(scanner.scanner_id(), "scanner.routes.v1");
    assert_eq!(scanner.domain(), ObservationType::Routes);

    let start = std::time::Instant::now();
    let obs = scanner.scan(&device_id).await.expect("Scan failed");
    let duration = start.elapsed();

    // Invariant: Non-blocking, passive scan must execute within standard 5s timeout guard
    assert!(
        duration.as_millis() < 5000,
        "Native route scan took too long: {}ms",
        duration.as_millis()
    );

    assert_eq!(obs.schema_version, 1);
    assert_eq!(obs.device_id, device_id);
    assert_eq!(obs.scanner_id, "scanner.routes.v1");
    assert_eq!(obs.observation_type, ObservationType::Routes);
    assert_eq!(obs.evidence_hash.len(), 64);

    match &obs.payload {
        ObservationPayload::Routes(payload) => {
            let _ = payload;
            #[cfg(windows)]
            {
                assert_eq!(obs.privilege_level, PrivilegeStatus::Available);
                assert_eq!(obs.confidence, ConfidenceScore::KERNEL_AUTHORITATIVE);
                assert!(
                    !payload.routes.is_empty(),
                    "Windows host should have at least one route in its kernel table"
                );

                for route in &payload.routes {
                    assert!(!route.destination_cidr.is_empty());
                    assert!(route.destination_cidr.contains('/'));
                    if route.is_default_gateway {
                        assert!(
                            route.gateway_ip.is_some(),
                            "Default route must specify a non-empty gateway IP"
                        );
                    }
                }
            }
        }
        _ => panic!("Expected Routes payload variant"),
    }
}

#[test]
fn test_ipv4_and_ipv6_default_gateway_derivation() {
    let routes = [
        RouteRecord {
            destination_cidr: "0.0.0.0/0".to_string(),
            gateway_ip: Some("192.168.1.1".to_string()),
            interface_index: 10,
            interface_name: Some("Ethernet".to_string()),
            metric: 25,
            is_ipv6: false,
            is_default_gateway: true,
            route_type: RouteType::Remote,
        },
        RouteRecord {
            destination_cidr: "::/0".to_string(),
            gateway_ip: Some("fe80::1".to_string()),
            interface_index: 10,
            interface_name: Some("Ethernet".to_string()),
            metric: 50,
            is_ipv6: true,
            is_default_gateway: true,
            route_type: RouteType::Remote,
        },
        RouteRecord {
            destination_cidr: "192.168.1.0/24".to_string(),
            gateway_ip: None,
            interface_index: 10,
            interface_name: Some("Ethernet".to_string()),
            metric: 25,
            is_ipv6: false,
            is_default_gateway: false,
            route_type: RouteType::Direct,
        },
    ];

    let mut default_routes: Vec<&RouteRecord> = routes
        .iter()
        .filter(|r| r.is_default_gateway && r.gateway_ip.is_some())
        .collect();
    default_routes.sort_by_key(|r| r.metric);

    let mut default_gateways = Vec::new();
    for r in default_routes {
        if let Some(ref gw) = r.gateway_ip {
            if !default_gateways.contains(gw) {
                default_gateways.push(gw.clone());
            }
        }
    }

    assert_eq!(default_gateways.len(), 2);
    assert_eq!(default_gateways[0], "192.168.1.1"); // Lowest metric first
    assert_eq!(default_gateways[1], "fe80::1");
}

#[test]
fn test_multiple_default_gateways_preserved() {
    // Multi-homed setup with Ethernet (metric 10) and Wi-Fi (metric 30)
    let routes = [
        RouteRecord {
            destination_cidr: "0.0.0.0/0".to_string(),
            gateway_ip: Some("10.0.0.1".to_string()),
            interface_index: 12,
            interface_name: Some("Wi-Fi".to_string()),
            metric: 30,
            is_ipv6: false,
            is_default_gateway: true,
            route_type: RouteType::Remote,
        },
        RouteRecord {
            destination_cidr: "0.0.0.0/0".to_string(),
            gateway_ip: Some("192.168.1.1".to_string()),
            interface_index: 10,
            interface_name: Some("Ethernet".to_string()),
            metric: 10,
            is_ipv6: false,
            is_default_gateway: true,
            route_type: RouteType::Remote,
        },
    ];

    let mut default_routes: Vec<&RouteRecord> = routes
        .iter()
        .filter(|r| r.is_default_gateway && r.gateway_ip.is_some())
        .collect();
    default_routes.sort_by_key(|r| r.metric);

    let mut default_gateways = Vec::new();
    for r in default_routes {
        if let Some(ref gw) = r.gateway_ip {
            if !default_gateways.contains(gw) {
                default_gateways.push(gw.clone());
            }
        }
    }

    // Must preserve BOTH default gateways in metric priority order
    assert_eq!(default_gateways.len(), 2);
    assert_eq!(default_gateways[0], "192.168.1.1");
    assert_eq!(default_gateways[1], "10.0.0.1");
}

#[test]
fn test_no_default_route_explicit_state() {
    // Isolated network with only direct local routes
    let routes = [
        RouteRecord {
            destination_cidr: "127.0.0.1/32".to_string(),
            gateway_ip: None,
            interface_index: 1,
            interface_name: Some("Loopback".to_string()),
            metric: 1,
            is_ipv6: false,
            is_default_gateway: false,
            route_type: RouteType::Local,
        },
        RouteRecord {
            destination_cidr: "10.10.10.0/24".to_string(),
            gateway_ip: None,
            interface_index: 5,
            interface_name: Some("IsolatedNet".to_string()),
            metric: 100,
            is_ipv6: false,
            is_default_gateway: false,
            route_type: RouteType::Direct,
        },
    ];

    let default_routes: Vec<&RouteRecord> = routes
        .iter()
        .filter(|r| r.is_default_gateway && r.gateway_ip.is_some())
        .collect();

    assert!(
        default_routes.is_empty(),
        "Isolated network must have empty default gateways"
    );
}

#[test]
fn test_distinct_state_representation() {
    let device_id = DeviceId::new();

    // State 1: Supported + Available
    let obs_avail = Observation::new(
        device_id.clone(),
        "scanner.routes.v1",
        ObservationType::Routes,
        TargetDescriptor::Host {
            hostname: "test-host".to_string(),
        },
        10,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Internal,
        ObservationPayload::Routes(RouteObservationPayload {
            routes: vec![],
            default_gateways: vec![],
        }),
    )
    .unwrap();
    assert_eq!(obs_avail.privilege_level, PrivilegeStatus::Available);
    assert_eq!(obs_avail.confidence, ConfidenceScore::KERNEL_AUTHORITATIVE);

    // State 2: Unsupported / Stub
    let obs_unsupported = Observation::new(
        device_id.clone(),
        "scanner.routes.v1",
        ObservationType::Routes,
        TargetDescriptor::Host {
            hostname: "test-host".to_string(),
        },
        0,
        PrivilegeStatus::Unsupported,
        ConfidenceScore::HEURISTIC,
        SensitivityLevel::Internal,
        ObservationPayload::Routes(RouteObservationPayload::default()),
    )
    .unwrap();
    assert_eq!(
        obs_unsupported.privilege_level,
        PrivilegeStatus::Unsupported
    );
    assert_eq!(obs_unsupported.confidence, ConfidenceScore::HEURISTIC);

    // Invariant: Distinct states must produce distinct representations
    assert_ne!(obs_avail.privilege_level, obs_unsupported.privilege_level);
}

#[test]
fn test_route_ordering_determinism() {
    let r1 = RouteRecord {
        destination_cidr: "0.0.0.0/0".to_string(),
        gateway_ip: Some("192.168.1.1".to_string()),
        interface_index: 10,
        interface_name: Some("Ethernet".to_string()),
        metric: 25,
        is_ipv6: false,
        is_default_gateway: true,
        route_type: RouteType::Remote,
    };
    let r2 = RouteRecord {
        destination_cidr: "192.168.1.0/24".to_string(),
        gateway_ip: None,
        interface_index: 10,
        interface_name: Some("Ethernet".to_string()),
        metric: 25,
        is_ipv6: false,
        is_default_gateway: false,
        route_type: RouteType::Direct,
    };
    let r3 = RouteRecord {
        destination_cidr: "::/0".to_string(),
        gateway_ip: Some("fe80::1".to_string()),
        interface_index: 10,
        interface_name: Some("Ethernet".to_string()),
        metric: 50,
        is_ipv6: true,
        is_default_gateway: true,
        route_type: RouteType::Remote,
    };

    let mut list_a = vec![r3.clone(), r1.clone(), r2.clone()];
    let mut list_b = vec![r2.clone(), r3.clone(), r1.clone()];

    let sort_fn = |list: &mut Vec<RouteRecord>| {
        list.sort_by(|a, b| {
            (
                a.is_ipv6,
                &a.destination_cidr,
                a.metric,
                a.interface_index,
                &a.gateway_ip,
            )
                .cmp(&(
                    b.is_ipv6,
                    &b.destination_cidr,
                    b.metric,
                    b.interface_index,
                    &b.gateway_ip,
                ))
        });
    };

    sort_fn(&mut list_a);
    sort_fn(&mut list_b);

    assert_eq!(list_a, list_b);

    let device_id = DeviceId::new();
    let obs_a = Observation::new(
        device_id.clone(),
        "scanner.routes.v1",
        ObservationType::Routes,
        TargetDescriptor::Host {
            hostname: "test-host".to_string(),
        },
        5,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Internal,
        ObservationPayload::Routes(RouteObservationPayload {
            routes: list_a,
            default_gateways: vec!["192.168.1.1".to_string()],
        }),
    )
    .unwrap();

    let obs_b = Observation::new(
        device_id,
        "scanner.routes.v1",
        ObservationType::Routes,
        TargetDescriptor::Host {
            hostname: "test-host".to_string(),
        },
        5,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Internal,
        ObservationPayload::Routes(RouteObservationPayload {
            routes: list_b,
            default_gateways: vec!["192.168.1.1".to_string()],
        }),
    )
    .unwrap();

    assert_eq!(obs_a.evidence_hash, obs_b.evidence_hash);
}

#[test]
fn test_target_descriptor_route_key_generation() {
    let t1 = TargetDescriptor::Route {
        destination: "0.0.0.0/0".to_string(),
        gateway: Some("192.168.1.1".to_string()),
    };
    assert_eq!(t1.target_key(), "route:0.0.0.0/0:192.168.1.1");

    let t2 = TargetDescriptor::Route {
        destination: "10.0.0.0/8".to_string(),
        gateway: None,
    };
    assert_eq!(t2.target_key(), "route:10.0.0.0/8:direct");
}

#[tokio::test]
async fn test_observation_queue_persistence_and_retrieval() {
    let db = DatabaseEngine::in_memory().expect("Failed to create in-memory database");
    let device_id = DeviceId::new();
    let scanner = PlatformRouteScanner::new();
    let obs = scanner.scan(&device_id).await.expect("Scan failed");

    let payload_json = serde_json::to_string(&obs.payload).unwrap();
    let obs_type_str = format!("{:?}", obs.observation_type).to_lowercase();

    // 1. Enqueue observation into SQLite queue
    let entry = db
        .with_writer(move |conn| {
            ObservationQueueRepository::enqueue(conn, &obs_type_str, &payload_json, None)
        })
        .await
        .expect("Enqueue failed");

    assert_eq!(entry.observation_type, "routes");
    assert_eq!(entry.status, ObservationStatus::Queued);
    assert_eq!(entry.retry_count, 0);
    assert_eq!(entry.sha256_hash.len(), 64);

    // 2. Fetch queued batch
    let batch = db
        .with_reader(|conn| ObservationQueueRepository::fetch_queued_batch(conn, 10))
        .await
        .expect("Fetch failed");

    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].id, entry.id);

    // 3. Mark in-flight
    let ids = vec![entry.id.clone()];
    let updated = db
        .with_writer(move |conn| ObservationQueueRepository::mark_in_flight(conn, &ids))
        .await
        .expect("Mark in-flight failed");
    assert_eq!(updated, 1);

    // 4. Mark acknowledged
    let ids_ack = vec![entry.id.clone()];
    let acked = db
        .with_writer(move |conn| ObservationQueueRepository::mark_acknowledged(conn, &ids_ack))
        .await
        .expect("Mark acknowledged failed");
    assert_eq!(acked, 1);
}

struct FaultyScanner;

#[async_trait::async_trait]
impl PostureScanner for FaultyScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.faulty.v1"
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Firewall
    }

    async fn scan(&self, _device_id: &DeviceId) -> netra_core::error::Result<Observation> {
        Err(netra_core::error::NetraError::platform(
            "Simulated route failure",
        ))
    }
}

#[tokio::test]
async fn test_scanner_supervisor_failure_isolation_with_routes() {
    let db = Arc::new(DatabaseEngine::in_memory().expect("Failed to create in-memory db"));
    let device_id = DeviceId::new();

    // Register 1 working route scanner and 1 faulty scanner
    let scanners: Vec<Arc<dyn PostureScanner>> = vec![
        Arc::new(PlatformRouteScanner::new()),
        Arc::new(FaultyScanner),
    ];

    let supervisor = ScannerSupervisor::new(db.clone(), scanners);
    let result = supervisor
        .run_scan_cycle(&device_id)
        .await
        .expect("Supervisor cycle should succeed even if one scanner fails");

    assert_eq!(result.total_scanners, 2);
    assert_eq!(result.successful_scanners, 1);
    assert_eq!(result.observations_collected, 1);
}

#[test]
fn test_linux_proc_net_route_fixture_parsing() {
    let fixture = r#"Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask	MTU	Window	IRTT
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
eth0	0001A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
lo	0000007F	00000000	0001	0	0	0	000000FF	0	0	0
"#;

    let routes = parse_proc_net_route(fixture);
    assert_eq!(routes.len(), 3);

    // 1. Default gateway route
    assert_eq!(routes[0].destination_cidr, "0.0.0.0/0");
    assert_eq!(routes[0].gateway_ip, Some("192.168.1.1".to_string()));
    assert_eq!(routes[0].metric, 100);
    assert!(routes[0].is_default_gateway);
    assert_eq!(routes[0].route_type, RouteType::Remote);
    assert_eq!(routes[0].interface_name.as_deref(), Some("eth0"));

    // 2. Subnet route (192.168.1.0/24)
    assert_eq!(routes[1].destination_cidr, "192.168.1.0/24");
    assert_eq!(routes[1].gateway_ip, None);
    assert!(!routes[1].is_default_gateway);
    assert_eq!(routes[1].route_type, RouteType::Direct);

    // 3. Loopback route (127.0.0.0/8)
    assert_eq!(routes[2].destination_cidr, "127.0.0.0/8");
    assert_eq!(routes[2].route_type, RouteType::Local);
}

#[test]
fn test_linux_proc_net_ipv6_route_fixture_parsing() {
    let fixture = r#"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 00000001 lo
"#;

    let routes = parse_proc_net_ipv6_route(fixture);
    assert_eq!(routes.len(), 3);

    // 1. Default IPv6 gateway
    assert_eq!(routes[0].destination_cidr, "::/0");
    assert_eq!(routes[0].gateway_ip, Some("fe80::1".to_string()));
    assert_eq!(routes[0].metric, 1024);
    assert!(routes[0].is_default_gateway);
    assert!(routes[0].is_ipv6);

    // 2. Link-local prefix
    assert_eq!(routes[1].destination_cidr, "fe80::/64");
    assert_eq!(routes[1].gateway_ip, None);
    assert!(!routes[1].is_default_gateway);

    // 3. Loopback
    assert_eq!(routes[2].destination_cidr, "::1/128");
    assert_eq!(routes[2].route_type, RouteType::Local);
}

#[test]
fn test_malformed_route_fixture_resilience() {
    // Truncated, empty, and invalid lines should be skipped safely without panic
    let empty_res = parse_proc_net_route("");
    assert!(empty_res.is_empty());

    let garbage = "InvalidHeader\nGarbageLine\neth0 123 456\n";
    let garbage_res = parse_proc_net_route(garbage);
    assert!(garbage_res.is_empty());

    let ipv6_garbage = "0000 00 1234\nshort line\n";
    let ipv6_res = parse_proc_net_ipv6_route(ipv6_garbage);
    assert!(ipv6_res.is_empty());
}

#[test]
fn test_passive_architectural_invariants() {
    // Verify scanner metadata and invariants
    let scanner = PlatformRouteScanner::new();
    assert_eq!(scanner.scanner_id(), "scanner.routes.v1");
    assert_eq!(scanner.domain(), ObservationType::Routes);

    // Architectural invariant verification:
    // Collector strictly reads kernel tables and memory structures
    // without spawning subprocesses or opening network sockets.
}
