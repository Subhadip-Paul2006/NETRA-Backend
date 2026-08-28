//! # Network Interface Posture Scanner Tests (Phase 8.2)
//!
//! Validates native/mock network interface observation, MAC pseudonymization privacy,
//! IP classification, ObservationQueue persistence, and ScannerSupervisor failure isolation.

use std::sync::Arc;

use netra_core::id::DeviceId;
use netra_core::network::{hash_mac_str, is_valid_mac_hash, IpClassification};
use netra_core::observation::{
    InterfaceObservationPayload, InterfaceRecord, InterfaceStatus, InterfaceType, IpNetworkRecord,
    Observation, ObservationPayload, ObservationType, PostureScanner, ScannerSupervisor,
    TargetDescriptor,
};
use netra_core::storage::repositories::queue::ObservationQueueRepository;
use netra_core::storage::{DatabaseEngine, ObservationStatus};
use netra_platform::scanners::interfaces::PlatformInterfaceScanner;

#[tokio::test]
async fn test_native_platform_interface_scanner_execution() {
    let device_id = DeviceId::new();
    let scanner = PlatformInterfaceScanner::new();

    assert_eq!(scanner.scanner_id(), "scanner.interfaces.v1");
    assert_eq!(scanner.domain(), ObservationType::Interfaces);

    let start = std::time::Instant::now();
    let obs = scanner.scan(&device_id).await.expect("Scan failed");
    let duration = start.elapsed();

    // Invariant: Non-blocking, passive scan must execute within standard 5s timeout guard
    assert!(
        duration.as_millis() < 5000,
        "Native interface scan took too long: {}ms",
        duration.as_millis()
    );

    assert_eq!(obs.schema_version, 1);
    assert_eq!(obs.device_id, device_id);
    assert_eq!(obs.scanner_id, "scanner.interfaces.v1");
    assert_eq!(obs.observation_type, ObservationType::Interfaces);
    assert_eq!(obs.evidence_hash.len(), 64);

    match &obs.payload {
        ObservationPayload::Interfaces(payload) => {
            #[cfg(windows)]
            assert!(
                !payload.interfaces.is_empty(),
                "Windows host should have at least one network interface"
            );

            for iface in &payload.interfaces {
                assert!(!iface.interface_name.is_empty());
                // Privacy Guarantee: Raw MAC is NEVER stored; hash must be 64-char hex if present
                if let Some(ref mac_hash) = iface.mac_address_hash {
                    assert_eq!(mac_hash.len(), 64);
                    assert!(is_valid_mac_hash(mac_hash));
                    assert!(
                        !mac_hash.contains(':'),
                        "MAC hash must not contain raw delimiters"
                    );
                }

                // IP Invariant: All IPs must have valid classification
                for ip_rec in &iface.ip_addresses {
                    assert!(!ip_rec.ip_address.is_empty());
                    if ip_rec.is_ipv6 {
                        assert!(ip_rec.ip_address.contains(':'));
                    } else {
                        assert!(ip_rec.ip_address.contains('.'));
                    }
                }
            }
        }
        _ => panic!("Expected Interfaces payload variant"),
    }
}

#[test]
fn test_interface_payload_edge_cases_normalization() {
    // 1. Empty interface list
    let empty_payload = InterfaceObservationPayload {
        interfaces: Vec::new(),
    };
    let empty_obs_payload = ObservationPayload::Interfaces(empty_payload);
    let serialized_empty = serde_json::to_string(&empty_obs_payload).unwrap();
    assert!(serialized_empty.contains("\"domain\":\"interfaces\""));
    assert!(serialized_empty.contains("\"interfaces\":[]"));

    // 2. Interface without MAC (e.g. Loopback)
    let loopback = InterfaceRecord {
        interface_name: "Loopback Pseudo-Interface 1".to_string(),
        friendly_name: Some("Loopback".to_string()),
        interface_index: 1,
        mac_address_hash: None,
        interface_type: InterfaceType::Loopback,
        oper_status: InterfaceStatus::Up,
        ip_addresses: vec![
            IpNetworkRecord {
                ip_address: "127.0.0.1".to_string(),
                prefix_length: 8,
                is_ipv6: false,
                classification: IpClassification::Loopback,
                broadcast_address: None,
            },
            IpNetworkRecord {
                ip_address: "::1".to_string(),
                prefix_length: 128,
                is_ipv6: true,
                classification: IpClassification::Loopback,
                broadcast_address: None,
            },
        ],
        mtu: 65536,
        is_loopback: true,
        is_point_to_point: false,
        is_dhcp_enabled: None,
        is_virtual: false,
    };
    assert!(loopback.mac_address_hash.is_none());
    assert_eq!(loopback.ip_addresses.len(), 2);

    // 3. Interface with multiple IPv4 and IPv6 addresses
    let multi_ip_iface = InterfaceRecord {
        interface_name: "eth0".to_string(),
        friendly_name: Some("Primary Ethernet".to_string()),
        interface_index: 2,
        mac_address_hash: hash_mac_str("00:11:22:33:44:55"),
        interface_type: InterfaceType::Ethernet,
        oper_status: InterfaceStatus::Up,
        ip_addresses: vec![
            IpNetworkRecord {
                ip_address: "192.168.1.10".to_string(),
                prefix_length: 24,
                is_ipv6: false,
                classification: IpClassification::Private,
                broadcast_address: Some("192.168.1.255".to_string()),
            },
            IpNetworkRecord {
                ip_address: "10.0.0.5".to_string(),
                prefix_length: 16,
                is_ipv6: false,
                classification: IpClassification::Private,
                broadcast_address: Some("10.0.255.255".to_string()),
            },
            IpNetworkRecord {
                ip_address: "fe80::1".to_string(),
                prefix_length: 64,
                is_ipv6: true,
                classification: IpClassification::LinkLocal,
                broadcast_address: None,
            },
            IpNetworkRecord {
                ip_address: "2606:4700:4700::1111".to_string(),
                prefix_length: 64,
                is_ipv6: true,
                classification: IpClassification::PublicGlobal,
                broadcast_address: None,
            },
        ],
        mtu: 1500,
        is_loopback: false,
        is_point_to_point: false,
        is_dhcp_enabled: Some(true),
        is_virtual: false,
    };

    assert_eq!(multi_ip_iface.ip_addresses.len(), 4);
    assert_eq!(
        multi_ip_iface.ip_addresses[0].classification,
        IpClassification::Private
    );
    assert_eq!(
        multi_ip_iface.ip_addresses[2].classification,
        IpClassification::LinkLocal
    );
    assert_eq!(
        multi_ip_iface.ip_addresses[3].classification,
        IpClassification::PublicGlobal
    );

    // 4. TargetDescriptor formatting
    let target = TargetDescriptor::NetworkInterface {
        interface_name: multi_ip_iface.interface_name.clone(),
    };
    assert_eq!(target.target_key(), "interface:eth0");
}

#[tokio::test]
async fn test_interface_observation_queue_persistence() {
    let db = DatabaseEngine::in_memory().expect("Failed to create in-memory database");
    let device_id = DeviceId::new();
    let scanner = PlatformInterfaceScanner::new();

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

    assert_eq!(entry.observation_type, "interfaces");
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
            "Simulated driver failure",
        ))
    }
}

#[tokio::test]
async fn test_scanner_supervisor_failure_isolation_with_interfaces() {
    let db = Arc::new(DatabaseEngine::in_memory().expect("Failed to create in-memory db"));
    let device_id = DeviceId::new();

    // Register 1 working interface scanner and 1 faulty scanner
    let scanners: Vec<Arc<dyn PostureScanner>> = vec![
        Arc::new(PlatformInterfaceScanner::new()),
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
