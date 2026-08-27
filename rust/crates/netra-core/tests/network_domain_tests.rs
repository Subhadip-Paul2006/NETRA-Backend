//! # Network Domain Contracts & Topology Tests (Phase 8.1)
//!
//! Validates network observation payloads, target descriptors, canonical evidence hashes,
//! IP classifications, MAC pseudonymization privacy, and deterministic topology synthesis.

use netra_core::id::DeviceId;
use netra_core::network::{
    hash_mac_bytes, hash_mac_str, is_valid_mac_hash, IpClassification, TopologyBuilder,
};
use netra_core::observation::{
    ConfidenceScore, DnsObservationPayload, DnsServerRecord, InterfaceObservationPayload,
    InterfaceRecord, InterfaceStatus, InterfaceType, IpNetworkRecord, NeighborObservationPayload,
    NeighborRecord, NeighborState, Observation, ObservationPayload, ObservationType,
    PrivilegeStatus, RouteObservationPayload, RouteRecord, RouteType, SensitivityLevel,
    TargetDescriptor,
};
use std::net::IpAddr;
use std::str::FromStr;

#[test]
fn test_ip_classification_comprehensive() {
    // IPv4 RFC mappings
    let cases_v4 = vec![
        ("127.0.0.1", IpClassification::Loopback),
        ("127.255.255.255", IpClassification::Loopback),
        ("10.0.0.1", IpClassification::Private),
        ("10.254.254.254", IpClassification::Private),
        ("172.16.0.1", IpClassification::Private),
        ("172.31.255.255", IpClassification::Private),
        ("192.168.0.1", IpClassification::Private),
        ("192.168.254.254", IpClassification::Private),
        ("169.254.1.1", IpClassification::LinkLocal),
        ("224.0.0.251", IpClassification::Multicast),
        ("239.255.255.250", IpClassification::Multicast),
        ("255.255.255.255", IpClassification::Broadcast),
        ("0.0.0.0", IpClassification::Unspecified),
        ("100.64.0.1", IpClassification::CarrierGradeNat),
        ("100.127.255.254", IpClassification::CarrierGradeNat),
        ("192.0.2.1", IpClassification::Documentation),
        ("198.51.100.1", IpClassification::Documentation),
        ("203.0.113.1", IpClassification::Documentation),
        ("1.1.1.1", IpClassification::PublicGlobal),
        ("8.8.8.8", IpClassification::PublicGlobal),
        ("142.250.190.46", IpClassification::PublicGlobal),
    ];

    for (ip_str, expected) in cases_v4 {
        let ip = IpAddr::from_str(ip_str).unwrap();
        assert_eq!(
            IpClassification::classify(&ip),
            expected,
            "Failed classification for IPv4 {}",
            ip_str
        );
    }

    // IPv6 RFC mappings
    let cases_v6 = vec![
        ("::1", IpClassification::Loopback),
        ("::", IpClassification::Unspecified),
        ("fe80::1", IpClassification::LinkLocal),
        ("fe80::dead:beef:cafe", IpClassification::LinkLocal),
        ("fc00::1", IpClassification::Private),
        ("fd12:3456:789a::1", IpClassification::Private),
        ("ff02::1", IpClassification::Multicast),
        ("2001:db8::1", IpClassification::Documentation),
        ("2606:4700:4700::1111", IpClassification::PublicGlobal),
    ];

    for (ip_str, expected) in cases_v6 {
        let ip = IpAddr::from_str(ip_str).unwrap();
        assert_eq!(
            IpClassification::classify(&ip),
            expected,
            "Failed classification for IPv6 {}",
            ip_str
        );
    }
}

#[test]
fn test_mac_pseudonymization_privacy_guarantees() {
    let mac_str1 = "00:1A:2B:3C:4D:5E";
    let mac_str2 = "00-1a-2b-3c-4d-5e";
    let mac_str3 = "001a2b3c4d5e";
    let mac_bytes = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];

    let hash1 = hash_mac_str(mac_str1).expect("Failed to hash colon MAC");
    let hash2 = hash_mac_str(mac_str2).expect("Failed to hash dash MAC");
    let hash3 = hash_mac_str(mac_str3).expect("Failed to hash raw hex string MAC");
    let hash_from_b = hash_mac_bytes(&mac_bytes);

    // All variations must produce identical pseudonymized SHA-256
    assert_eq!(hash1, hash2);
    assert_eq!(hash2, hash3);
    assert_eq!(hash3, hash_from_b);

    // Verify hash length and character set
    assert_eq!(hash1.len(), 64);
    assert!(is_valid_mac_hash(&hash1));

    // Verify that empty or zero MACs return None / empty string
    assert_eq!(hash_mac_bytes(&[0, 0, 0, 0, 0, 0]), "");
    assert_eq!(hash_mac_str("00:00:00:00:00:00"), None);
    assert_eq!(hash_mac_str("not_a_mac"), None);
}

#[test]
fn test_network_observations_envelope_and_evidence_hashing() {
    let device_id = DeviceId::new();

    // 1. Interfaces Observation
    let iface_payload = ObservationPayload::Interfaces(InterfaceObservationPayload {
        interfaces: vec![InterfaceRecord {
            interface_name: "eth0".to_string(),
            friendly_name: Some("Ethernet 1".to_string()),
            interface_index: 2,
            mac_address_hash: hash_mac_str("aa:bb:cc:dd:ee:ff"),
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
            is_dhcp_enabled: Some(true),
            is_virtual: false,
        }],
    });

    let obs_iface = Observation::new(
        device_id.clone(),
        "scanner.interfaces.v1",
        ObservationType::Interfaces,
        TargetDescriptor::NetworkInterface {
            interface_name: "eth0".to_string(),
        },
        12,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Internal,
        iface_payload.clone(),
    )
    .unwrap();

    assert_eq!(obs_iface.observation_type, ObservationType::Interfaces);
    assert_eq!(obs_iface.target.target_key(), "interface:eth0");
    assert_eq!(obs_iface.evidence_hash.len(), 64);
    assert_eq!(
        obs_iface.evidence_hash,
        Observation::compute_evidence_hash(&iface_payload).unwrap()
    );

    // 2. Routes Observation
    let route_payload = ObservationPayload::Routes(RouteObservationPayload {
        routes: vec![RouteRecord {
            destination_cidr: "0.0.0.0/0".to_string(),
            gateway_ip: Some("192.168.1.1".to_string()),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 10,
            is_ipv6: false,
            is_default_gateway: true,
            route_type: RouteType::Remote,
        }],
        default_gateways: vec!["192.168.1.1".to_string()],
    });

    let obs_routes = Observation::new(
        device_id.clone(),
        "scanner.routes.v1",
        ObservationType::Routes,
        TargetDescriptor::Route {
            destination: "0.0.0.0/0".to_string(),
            gateway: Some("192.168.1.1".to_string()),
        },
        8,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Internal,
        route_payload.clone(),
    )
    .unwrap();

    assert_eq!(obs_routes.observation_type, ObservationType::Routes);
    assert_eq!(
        obs_routes.target.target_key(),
        "route:0.0.0.0/0:192.168.1.1"
    );
    assert_eq!(obs_routes.evidence_hash.len(), 64);

    // 3. DNS Observation
    let dns_payload = ObservationPayload::Dns(DnsObservationPayload {
        dns_servers: vec![DnsServerRecord {
            server_address: "1.1.1.1".to_string(),
            interface_name: Some("eth0".to_string()),
            is_ipv6: false,
            classification: IpClassification::PublicGlobal,
        }],
        search_domains: vec!["corp.local".to_string()],
        is_dynamic_dns_enabled: None,
    });

    let obs_dns = Observation::new(
        device_id.clone(),
        "scanner.dns.v1",
        ObservationType::Dns,
        TargetDescriptor::DnsServer {
            server_address: "1.1.1.1".to_string(),
        },
        5,
        PrivilegeStatus::Available,
        ConfidenceScore::SYSTEM_TABLE,
        SensitivityLevel::Internal,
        dns_payload.clone(),
    )
    .unwrap();

    assert_eq!(obs_dns.observation_type, ObservationType::Dns);
    assert_eq!(obs_dns.target.target_key(), "dns_server:1.1.1.1");

    // 4. Neighbors Observation
    let neighbor_payload = ObservationPayload::Neighbors(NeighborObservationPayload {
        neighbors: vec![NeighborRecord {
            ip_address: "192.168.1.1".to_string(),
            mac_address_hash: hash_mac_str("11:22:33:44:55:66"),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            state: NeighborState::Reachable,
            is_ipv6: false,
            ip_classification: IpClassification::Private,
            is_router: Some(true),
        }],
    });

    let obs_neighbors = Observation::new(
        device_id,
        "scanner.neighbors.v1",
        ObservationType::Neighbors,
        TargetDescriptor::NetworkNeighbor {
            ip_address: "192.168.1.1".to_string(),
            interface_name: "eth0".to_string(),
        },
        6,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Confidential,
        neighbor_payload.clone(),
    )
    .unwrap();

    assert_eq!(obs_neighbors.observation_type, ObservationType::Neighbors);
    assert_eq!(
        obs_neighbors.target.target_key(),
        "neighbor:eth0:192.168.1.1"
    );
}

#[test]
fn test_deterministic_multi_homed_topology_synthesis() {
    let device_id = DeviceId::new();

    // Setup multi-homed system (two active non-loopback interfaces on different subnets)
    let iface_payload = InterfaceObservationPayload {
        interfaces: vec![
            InterfaceRecord {
                interface_name: "eth0".to_string(),
                friendly_name: Some("Corporate LAN".to_string()),
                interface_index: 2,
                mac_address_hash: hash_mac_str("00:11:22:33:44:55"),
                interface_type: InterfaceType::Ethernet,
                oper_status: InterfaceStatus::Up,
                ip_addresses: vec![IpNetworkRecord {
                    ip_address: "10.100.1.20".to_string(),
                    prefix_length: 24,
                    is_ipv6: false,
                    classification: IpClassification::Private,
                    broadcast_address: Some("10.100.1.255".to_string()),
                }],
                mtu: 1500,
                is_loopback: false,
                is_point_to_point: false,
                is_dhcp_enabled: Some(true),
                is_virtual: false,
            },
            InterfaceRecord {
                interface_name: "wlan0".to_string(),
                friendly_name: Some("Guest Wi-Fi".to_string()),
                interface_index: 3,
                mac_address_hash: hash_mac_str("66:77:88:99:aa:bb"),
                interface_type: InterfaceType::Wireless,
                oper_status: InterfaceStatus::Up,
                ip_addresses: vec![IpNetworkRecord {
                    ip_address: "192.168.200.15".to_string(),
                    prefix_length: 24,
                    is_ipv6: false,
                    classification: IpClassification::Private,
                    broadcast_address: Some("192.168.200.255".to_string()),
                }],
                mtu: 1500,
                is_loopback: false,
                is_point_to_point: false,
                is_dhcp_enabled: Some(true),
                is_virtual: false,
            },
        ],
    };

    let routes_payload = RouteObservationPayload {
        routes: vec![
            RouteRecord {
                destination_cidr: "0.0.0.0/0".to_string(),
                gateway_ip: Some("10.100.1.1".to_string()),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                metric: 10,
                is_ipv6: false,
                is_default_gateway: true,
                route_type: RouteType::Remote,
            },
            RouteRecord {
                destination_cidr: "0.0.0.0/0".to_string(),
                gateway_ip: Some("192.168.200.1".to_string()),
                interface_index: 3,
                interface_name: Some("wlan0".to_string()),
                metric: 20,
                is_ipv6: false,
                is_default_gateway: true,
                route_type: RouteType::Remote,
            },
        ],
        default_gateways: vec!["10.100.1.1".to_string(), "192.168.200.1".to_string()],
    };

    let dns_payload = DnsObservationPayload {
        dns_servers: vec![
            DnsServerRecord {
                server_address: "10.100.1.5".to_string(),
                interface_name: Some("eth0".to_string()),
                is_ipv6: false,
                classification: IpClassification::Private,
            },
            DnsServerRecord {
                server_address: "1.1.1.1".to_string(),
                interface_name: Some("wlan0".to_string()),
                is_ipv6: false,
                classification: IpClassification::PublicGlobal,
            },
        ],
        search_domains: vec!["corp.local".to_string()],
        is_dynamic_dns_enabled: None,
    };

    let neighbor_payload = NeighborObservationPayload {
        neighbors: vec![
            NeighborRecord {
                ip_address: "10.100.1.1".to_string(),
                mac_address_hash: hash_mac_str("aa:11:22:33:44:55"),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                state: NeighborState::Reachable,
                is_ipv6: false,
                ip_classification: IpClassification::Private,
                is_router: Some(true),
            },
            NeighborRecord {
                ip_address: "192.168.200.1".to_string(),
                mac_address_hash: hash_mac_str("bb:22:33:44:55:66"),
                interface_index: 3,
                interface_name: Some("wlan0".to_string()),
                state: NeighborState::Reachable,
                is_ipv6: false,
                ip_classification: IpClassification::Private,
                is_router: Some(true),
            },
        ],
    };

    let snapshot = TopologyBuilder::build(
        device_id,
        Some(&iface_payload),
        Some(&routes_payload),
        Some(&dns_payload),
        Some(&neighbor_payload),
    );

    assert!(
        snapshot.is_multi_homed,
        "Snapshot must detect multi-homed system"
    );
    assert_eq!(snapshot.interfaces.len(), 2);
    assert_eq!(snapshot.default_gateways.len(), 2);
    assert_eq!(snapshot.default_gateways[0].gateway_ip, "10.100.1.1"); // Lowest metric first
    assert_eq!(snapshot.default_gateways[1].gateway_ip, "192.168.200.1");
    assert_eq!(snapshot.subnets.len(), 2);
    assert_eq!(snapshot.dns_resolvers.len(), 2);
    assert_eq!(snapshot.neighbors.len(), 2);
    assert_eq!(snapshot.confidence, ConfidenceScore::KERNEL_AUTHORITATIVE);
    assert_eq!(snapshot.provenance_sources.len(), 4);
}
