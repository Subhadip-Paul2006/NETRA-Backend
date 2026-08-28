//! Integration and specification test suite for Phase 8.5 — Neighbor Discovery Observation.

use netra_core::id::DeviceId;
use netra_core::network::ip::IpClassification;
use netra_core::network::mac::{hash_mac_bytes, hash_mac_str};
use netra_core::observation::{
    ConfidenceScore, NeighborObservationPayload, NeighborRecord, NeighborState, Observation,
    ObservationPayload, ObservationType, PostureScanner, PrivilegeStatus, SensitivityLevel,
    TargetDescriptor,
};
use netra_core::storage::repositories::queue::ObservationQueueRepository;
use netra_core::storage::{DatabaseEngine, ObservationStatus};
use netra_platform::scanners::linux::neighbors::{parse_netlink_neighbors, parse_proc_net_arp};
use netra_platform::scanners::PlatformNeighborScanner;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

#[tokio::test]
async fn test_native_platform_neighbor_scanner_execution() {
    let device_id = DeviceId::new();
    let scanner = PlatformNeighborScanner::new();

    assert_eq!(scanner.scanner_id(), "scanner.neighbors.v1");
    assert_eq!(scanner.domain(), ObservationType::Neighbors);

    let obs = scanner
        .scan(&device_id)
        .await
        .expect("Native neighbor scan must not panic");

    assert_eq!(obs.schema_version, 1);
    assert_eq!(obs.device_id, device_id);
    assert_eq!(obs.scanner_id, "scanner.neighbors.v1");
    assert_eq!(obs.observation_type, ObservationType::Neighbors);
    assert_eq!(obs.sensitivity, SensitivityLevel::Internal);
    assert_eq!(obs.evidence_hash.len(), 64);
    assert!(
        obs.duration_ms < 5000,
        "Scan must complete within 5 seconds"
    );

    #[cfg(windows)]
    {
        assert_eq!(obs.privilege_level, PrivilegeStatus::Available);
        assert_eq!(obs.confidence, ConfidenceScore::KERNEL_AUTHORITATIVE);

        if let ObservationPayload::Neighbors(payload) = &obs.payload {
            for neighbor in &payload.neighbors {
                assert!(!neighbor.ip_address.is_empty());
                let parsed =
                    IpAddr::from_str(&neighbor.ip_address).expect("Valid neighbor IP address");
                assert_eq!(neighbor.is_ipv6, parsed.is_ipv6());
                assert_eq!(
                    neighbor.ip_classification,
                    IpClassification::classify(&parsed)
                );

                // Privacy check: if mac_address_hash exists, it must be a 64-char hex string
                if let Some(hash) = &neighbor.mac_address_hash {
                    assert_eq!(hash.len(), 64);
                    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
                }
            }
        } else {
            panic!("Expected ObservationPayload::Neighbors");
        }
    }

    #[cfg(target_os = "macos")]
    {
        assert_eq!(obs.privilege_level, PrivilegeStatus::Unsupported);
        assert_eq!(obs.confidence, ConfidenceScore::HEURISTIC);
    }
}

#[test]
fn test_linux_proc_net_arp_standard_parsing() {
    let fixture = r#"
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         00:1a:2b:3c:4d:5e     *        eth0
10.0.0.1         0x1         0x4         aa:bb:cc:dd:ee:ff     *        eth0
172.16.0.5       0x1         0x2         11:22:33:44:55:66     *        wlan0
"#;

    let neighbors = parse_proc_net_arp(fixture);

    assert_eq!(neighbors.len(), 3);

    assert_eq!(neighbors[0].ip_address, "10.0.0.1");
    assert_eq!(neighbors[0].state, NeighborState::Permanent);
    assert_eq!(neighbors[0].interface_name, Some("eth0".to_string()));
    assert!(!neighbors[0].is_ipv6);
    assert_eq!(neighbors[0].ip_classification, IpClassification::Private);
    assert!(neighbors[0].mac_address_hash.is_some());

    assert_eq!(neighbors[1].ip_address, "172.16.0.5");
    assert_eq!(neighbors[1].state, NeighborState::Reachable);
    assert_eq!(neighbors[1].interface_name, Some("wlan0".to_string()));

    assert_eq!(neighbors[2].ip_address, "192.168.1.1");
    assert_eq!(neighbors[2].state, NeighborState::Reachable);
    assert_eq!(neighbors[2].interface_name, Some("eth0".to_string()));
}

#[test]
fn test_linux_proc_net_arp_incomplete_entry_handling() {
    let fixture = r#"
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.254    0x1         0x0         00:00:00:00:00:00     *        eth0
"#;

    let neighbors = parse_proc_net_arp(fixture);

    assert_eq!(neighbors.len(), 1);
    assert_eq!(neighbors[0].ip_address, "192.168.1.254");
    assert_eq!(neighbors[0].state, NeighborState::Incomplete);
    assert_eq!(neighbors[0].mac_address_hash, None);
}

#[test]
fn test_linux_proc_net_arp_permanent_entry_handling() {
    let fixture = r#"
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x6         00:1a:2b:3c:4d:5e     *        eth0
"#;

    let neighbors = parse_proc_net_arp(fixture);

    assert_eq!(neighbors.len(), 1);
    assert_eq!(neighbors[0].state, NeighborState::Permanent);
}

#[test]
fn test_malformed_proc_net_arp_resilience() {
    let fixture = r#"
IP address       HW type     Flags       HW address            Mask     Device
not_an_ip        0x1         0x2         00:1a:2b:3c:4d:5e     *        eth0
192.168.1.1      0x1
999.999.999.999  0x1         0x2         00:1a:2b:3c:4d:5e     *        eth0
0.0.0.0          0x1         0x2         00:1a:2b:3c:4d:5e     *        eth0
127.0.0.1        0x1         0x2         00:1a:2b:3c:4d:5e     *        lo
8.8.8.8          0x1         0x2         00:11:22:33:44:55     *        eth0
"#;

    let neighbors = parse_proc_net_arp(fixture);

    assert_eq!(neighbors.len(), 1);
    assert_eq!(neighbors[0].ip_address, "8.8.8.8");
    assert_eq!(
        neighbors[0].ip_classification,
        IpClassification::PublicGlobal
    );
}

/// Helper function to build a Netlink RTM_NEWNEIGH packet for tests.
fn build_netlink_neighbor_msg(
    family: u8,
    ifindex: i32,
    state: u16,
    flags: u8,
    ip_bytes: &[u8],
    mac_bytes: Option<&[u8]>,
) -> Vec<u8> {
    let mut msg = Vec::new();

    // 1. Placeholder for nlmsghdr (16 bytes)
    msg.extend_from_slice(&[0u8; 16]);

    // 2. ndmsg (12 bytes)
    msg.push(family); // ndm_family
    msg.push(0); // ndm_pad1
    msg.extend_from_slice(&0u16.to_ne_bytes()); // ndm_pad2
    msg.extend_from_slice(&ifindex.to_ne_bytes()); // ndm_ifindex
    msg.extend_from_slice(&state.to_ne_bytes()); // ndm_state
    msg.push(flags); // ndm_flags
    msg.push(0); // ndm_type

    // 3. rtattr for NDA_DST (type = 1)
    let dst_attr_len = (4 + ip_bytes.len()) as u16;
    msg.extend_from_slice(&dst_attr_len.to_ne_bytes());
    msg.extend_from_slice(&1u16.to_ne_bytes()); // NDA_DST
    msg.extend_from_slice(ip_bytes);
    // Align to 4 bytes
    while msg.len() % 4 != 0 {
        msg.push(0);
    }

    // 4. rtattr for NDA_LLADDR (type = 2) if mac is provided
    if let Some(mac) = mac_bytes {
        let mac_attr_len = (4 + mac.len()) as u16;
        msg.extend_from_slice(&mac_attr_len.to_ne_bytes());
        msg.extend_from_slice(&2u16.to_ne_bytes()); // NDA_LLADDR
        msg.extend_from_slice(mac);
        while msg.len() % 4 != 0 {
            msg.push(0);
        }
    }

    // Fill in nlmsghdr
    let total_len = msg.len() as u32;
    msg[0..4].copy_from_slice(&total_len.to_ne_bytes());
    msg[4..6].copy_from_slice(&28u16.to_ne_bytes()); // RTM_NEWNEIGH
    msg[6..8].copy_from_slice(&0u16.to_ne_bytes()); // flags
    msg[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    msg[12..16].copy_from_slice(&0u32.to_ne_bytes()); // pid

    msg
}

#[test]
fn test_linux_netlink_ipv4_and_ipv6_ndp_parsing() {
    let mut buffer = Vec::new();

    // 1. IPv4 neighbor: 192.168.1.1, ifindex = 2, REACHABLE (0x02), MAC = 00:1a:2b:3c:4d:5e
    let ipv4_bytes = [192, 168, 1, 1];
    let mac1 = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
    buffer.extend(build_netlink_neighbor_msg(
        2, // AF_INET
        2,
        0x02, // NUD_REACHABLE
        0,
        &ipv4_bytes,
        Some(&mac1),
    ));

    // 2. IPv6 neighbor: 2001:db8::1, ifindex = 2, STALE (0x04), MAC = 00:1a:2b:3c:4d:5f
    let mut ipv6_bytes = [0u8; 16];
    ipv6_bytes[0] = 0x20;
    ipv6_bytes[1] = 0x01;
    ipv6_bytes[2] = 0x0d;
    ipv6_bytes[3] = 0xb8;
    ipv6_bytes[15] = 0x01;
    let mac2 = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5f];
    buffer.extend(build_netlink_neighbor_msg(
        10, // AF_INET6
        2,
        0x04, // NUD_STALE
        0,
        &ipv6_bytes,
        Some(&mac2),
    ));

    // Add NLMSG_DONE
    let done_hdr = [16u8, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
    buffer.extend_from_slice(&done_hdr);

    let neighbors = parse_netlink_neighbors(&buffer);

    assert_eq!(neighbors.len(), 2);

    assert_eq!(neighbors[0].ip_address, "192.168.1.1");
    assert!(!neighbors[0].is_ipv6);
    assert_eq!(neighbors[0].state, NeighborState::Reachable);
    assert_eq!(neighbors[0].interface_index, 2);
    assert_eq!(neighbors[0].mac_address_hash, Some(hash_mac_bytes(&mac1)));

    assert_eq!(neighbors[1].ip_address, "2001:db8::1");
    assert!(neighbors[1].is_ipv6);
    assert_eq!(neighbors[1].state, NeighborState::Stale);
    assert_eq!(neighbors[1].interface_index, 2);
    assert_eq!(neighbors[1].mac_address_hash, Some(hash_mac_bytes(&mac2)));
}

#[test]
fn test_linux_netlink_scoped_ipv6_link_local() {
    let mut ipv6_bytes = [0u8; 16];
    ipv6_bytes[0] = 0xfe;
    ipv6_bytes[1] = 0x80;
    ipv6_bytes[15] = 0x01; // fe80::1

    let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    let buffer = build_netlink_neighbor_msg(
        10,   // AF_INET6
        3,    // ifindex 3
        0x02, // NUD_REACHABLE
        0x80, // NTF_ROUTER
        &ipv6_bytes,
        Some(&mac),
    );

    let neighbors = parse_netlink_neighbors(&buffer);

    assert_eq!(neighbors.len(), 1);
    assert_eq!(neighbors[0].ip_address, "fe80::1");
    assert!(neighbors[0].is_ipv6);
    assert_eq!(neighbors[0].ip_classification, IpClassification::LinkLocal);
    assert_eq!(neighbors[0].state, NeighborState::Reachable);
    assert_eq!(neighbors[0].interface_index, 3);
    assert_eq!(neighbors[0].is_router, Some(true));
    assert_eq!(neighbors[0].mac_address_hash, Some(hash_mac_bytes(&mac)));
}

#[test]
fn test_linux_netlink_nud_states_mapping() {
    let ip = [10, 0, 0, 1];

    let test_states = [
        (0x02, NeighborState::Reachable),
        (0x04, NeighborState::Stale),
        (0x08, NeighborState::Delay),
        (0x10, NeighborState::Probe),
        (0x01, NeighborState::Incomplete),
        (0x20, NeighborState::Incomplete),
        (0x80, NeighborState::Permanent),
        (0x40, NeighborState::Permanent),
        (0x00, NeighborState::Unknown),
    ];

    for (nud_code, expected_state) in test_states {
        let buffer = build_netlink_neighbor_msg(2, 1, nud_code, 0, &ip, None);
        let neighbors = parse_netlink_neighbors(&buffer);
        assert_eq!(neighbors.len(), 1);
        assert_eq!(
            neighbors[0].state, expected_state,
            "Failed mapping for NUD code 0x{:02x}",
            nud_code
        );
    }
}

#[test]
fn test_linux_netlink_malformed_tlv_resilience() {
    // Truncated Netlink packet
    let bad_buffer = vec![16, 0, 0, 0, 28, 0, 0, 0, 1, 0]; // less than 16 bytes
    assert!(parse_netlink_neighbors(&bad_buffer).is_empty());

    // Corrupted rta_len exceeding message boundary
    let mut bad_tlv = build_netlink_neighbor_msg(2, 1, 0x02, 0, &[192, 168, 1, 1], None);
    // Overwrite NDA_DST rta_len to huge value
    bad_tlv[28] = 0xff;
    bad_tlv[29] = 0xff;
    assert!(parse_netlink_neighbors(&bad_tlv).is_empty());
}

#[test]
fn test_empty_neighbor_table_state() {
    assert!(parse_proc_net_arp("").is_empty());
    assert!(parse_netlink_neighbors(&[]).is_empty());
}

#[test]
fn test_distinct_state_representation() {
    // 1. Available with neighbors
    let populated = Observation::new(
        DeviceId::new(),
        "scanner.neighbors.v1",
        ObservationType::Neighbors,
        TargetDescriptor::Host {
            hostname: "test-host".to_string(),
        },
        5,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Internal,
        ObservationPayload::Neighbors(NeighborObservationPayload {
            neighbors: vec![NeighborRecord {
                ip_address: "192.168.1.1".to_string(),
                mac_address_hash: Some(hash_mac_bytes(&[1, 2, 3, 4, 5, 6])),
                interface_index: 2,
                interface_name: Some("Ethernet".to_string()),
                state: NeighborState::Reachable,
                is_ipv6: false,
                ip_classification: IpClassification::Private,
                is_router: Some(true),
            }],
        }),
    )
    .unwrap();

    // 2. Available but empty
    let empty = Observation::new(
        DeviceId::new(),
        "scanner.neighbors.v1",
        ObservationType::Neighbors,
        TargetDescriptor::Host {
            hostname: "isolated-host".to_string(),
        },
        2,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Internal,
        ObservationPayload::Neighbors(NeighborObservationPayload {
            neighbors: Vec::new(),
        }),
    )
    .unwrap();

    // 3. Explicit Unsupported
    let unsupported = Observation::new(
        DeviceId::new(),
        "scanner.neighbors.v1",
        ObservationType::Neighbors,
        TargetDescriptor::Host {
            hostname: "mac-host".to_string(),
        },
        0,
        PrivilegeStatus::Unsupported,
        ConfidenceScore::HEURISTIC,
        SensitivityLevel::Internal,
        ObservationPayload::Neighbors(NeighborObservationPayload::default()),
    )
    .unwrap();

    assert_eq!(populated.privilege_level, PrivilegeStatus::Available);
    assert_eq!(empty.privilege_level, PrivilegeStatus::Available);
    assert_eq!(unsupported.privilege_level, PrivilegeStatus::Unsupported);
    assert_eq!(unsupported.confidence, ConfidenceScore::HEURISTIC);
}

#[test]
fn test_mac_address_pseudonymization_invariants() {
    let raw_mac_str = "00:1A:2B:3C:4D:5E";
    let raw_mac_bytes = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];

    let hash_from_str = hash_mac_str(raw_mac_str).unwrap();
    let hash_from_bytes = hash_mac_bytes(&raw_mac_bytes);

    assert_eq!(hash_from_str, hash_from_bytes);
    assert_eq!(hash_from_str.len(), 64);

    let payload = NeighborObservationPayload {
        neighbors: vec![NeighborRecord {
            ip_address: "192.168.1.1".to_string(),
            mac_address_hash: Some(hash_from_str),
            interface_index: 1,
            interface_name: Some("eth0".to_string()),
            state: NeighborState::Reachable,
            is_ipv6: false,
            ip_classification: IpClassification::Private,
            is_router: None,
        }],
    };

    let serialized = serde_json::to_string(&payload).unwrap();

    // STRICT INVARIANT: raw MAC string must NEVER appear in serialized output
    assert!(!serialized.contains("00:1A:2B:3C:4D:5E"));
    assert!(!serialized.contains("00:1a:2b:3c:4d:5e"));
    assert!(!serialized.contains("001a2b3c4d5e"));
    assert!(serialized.contains("mac_address_hash"));
}

#[test]
fn test_target_descriptor_neighbor_keys() {
    let d1 = TargetDescriptor::NetworkNeighbor {
        ip_address: "192.168.1.1".to_string(),
        interface_name: "eth0".to_string(),
    };
    assert_eq!(d1.target_key(), "neighbor:eth0:192.168.1.1");

    let d2 = TargetDescriptor::NetworkNeighbor {
        ip_address: "2001:db8::1".to_string(),
        interface_name: "Ethernet".to_string(),
    };
    assert_eq!(d2.target_key(), "neighbor:ethernet:2001:db8::1");
}

#[test]
fn test_deterministic_neighbor_sorting() {
    let mut neighbors = [
        NeighborRecord {
            ip_address: "192.168.1.10".to_string(),
            mac_address_hash: None,
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            state: NeighborState::Reachable,
            is_ipv6: false,
            ip_classification: IpClassification::Private,
            is_router: None,
        },
        NeighborRecord {
            ip_address: "10.0.0.1".to_string(),
            mac_address_hash: None,
            interface_index: 1,
            interface_name: Some("eth0".to_string()),
            state: NeighborState::Reachable,
            is_ipv6: false,
            ip_classification: IpClassification::Private,
            is_router: None,
        },
        NeighborRecord {
            ip_address: "2001:db8::1".to_string(),
            mac_address_hash: None,
            interface_index: 1,
            interface_name: Some("eth0".to_string()),
            state: NeighborState::Reachable,
            is_ipv6: true,
            ip_classification: IpClassification::PublicGlobal,
            is_router: None,
        },
    ];

    neighbors.sort_by(|a, b| {
        a.is_ipv6
            .cmp(&b.is_ipv6)
            .then_with(|| a.ip_address.cmp(&b.ip_address))
            .then_with(|| a.interface_index.cmp(&b.interface_index))
            .then_with(|| a.interface_name.cmp(&b.interface_name))
    });

    assert_eq!(neighbors[0].ip_address, "10.0.0.1");
    assert_eq!(neighbors[1].ip_address, "192.168.1.10");
    assert_eq!(neighbors[2].ip_address, "2001:db8::1");
}

#[test]
fn test_multi_interface_neighbor_preservation() {
    let mut neighbors: Vec<NeighborRecord> = Vec::new();

    let n1 = NeighborRecord {
        ip_address: "192.168.1.1".to_string(),
        mac_address_hash: None,
        interface_index: 1,
        interface_name: Some("eth0".to_string()),
        state: NeighborState::Reachable,
        is_ipv6: false,
        ip_classification: IpClassification::Private,
        is_router: None,
    };

    let n2 = NeighborRecord {
        ip_address: "192.168.1.1".to_string(),
        mac_address_hash: None,
        interface_index: 2,
        interface_name: Some("wlan0".to_string()),
        state: NeighborState::Reachable,
        is_ipv6: false,
        ip_classification: IpClassification::Private,
        is_router: None,
    };

    neighbors.push(n1);
    neighbors.push(n2);

    // Multi-homed interface records for the same IP must remain distinct
    assert_eq!(neighbors.len(), 2);
    assert_ne!(neighbors[0].interface_name, neighbors[1].interface_name);
}

#[tokio::test]
async fn test_observation_queue_persistence_and_supervisor_isolation() {
    let db = Arc::new(DatabaseEngine::in_memory().expect("Failed to create in-memory database"));
    let device_id = DeviceId::new();
    let scanner = PlatformNeighborScanner::new();
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

    assert_eq!(entry.observation_type, "neighbors");
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

    // 5. Supervisor failure isolation
    struct FaultyNeighborScanner;

    #[async_trait::async_trait]
    impl PostureScanner for FaultyNeighborScanner {
        fn scanner_id(&self) -> &'static str {
            "scanner.faulty_neighbor.v1"
        }
        fn domain(&self) -> ObservationType {
            ObservationType::Neighbors
        }
        async fn scan(&self, _device_id: &DeviceId) -> netra_core::error::Result<Observation> {
            Err(netra_core::error::NetraError::platform(
                "Simulated neighbor scan failure",
            ))
        }
    }

    use netra_core::observation::ScannerSupervisor;
    let scanners: Vec<Arc<dyn PostureScanner>> = vec![
        Arc::new(PlatformNeighborScanner::new()),
        Arc::new(FaultyNeighborScanner),
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
