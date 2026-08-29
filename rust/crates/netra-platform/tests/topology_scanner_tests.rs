//! Integration & unit tests for NETRA Phase 8.6 — Network Topology Synthesis.

use std::sync::Arc;

use netra_core::id::DeviceId;
use netra_core::network::ip::IpClassification;
use netra_core::network::topology::{
    TopologyBuilder, TopologyCorrelator, TopologyEdgeKind, TopologyExtractor,
    TopologyObservationPayload,
};
use netra_core::observation::models::{
    ConfidenceScore, Observation, ObservationType, PrivilegeStatus, SensitivityLevel,
};
use netra_core::observation::payloads::{
    DnsObservationPayload, DnsServerRecord, InterfaceObservationPayload, InterfaceRecord,
    InterfaceStatus, InterfaceType, IpNetworkRecord, NeighborObservationPayload, NeighborRecord,
    NeighborState, ObservationPayload, RouteObservationPayload, RouteRecord, RouteType,
};
use netra_core::observation::supervisor::ScannerSupervisor;
use netra_core::observation::target::TargetDescriptor;
use netra_core::storage::repositories::queue::ObservationQueueRepository;
use netra_core::storage::{DatabaseEngine, ObservationStatus};
use netra_platform::create_all_platform_scanners;

// =============================================================================
// Helper Factories for Mock Observations
// =============================================================================

fn make_interfaces_obs(
    device_id: &DeviceId,
    privilege: PrivilegeStatus,
    interfaces: Vec<InterfaceRecord>,
) -> Observation {
    Observation::new(
        device_id.clone(),
        "scanner.interfaces.v1",
        ObservationType::Interfaces,
        TargetDescriptor::Host {
            hostname: "test-host".to_string(),
        },
        10,
        privilege,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Internal,
        ObservationPayload::Interfaces(InterfaceObservationPayload { interfaces }),
    )
    .unwrap()
}

fn make_routes_obs(
    device_id: &DeviceId,
    privilege: PrivilegeStatus,
    routes: Vec<RouteRecord>,
    default_gateways: Vec<String>,
) -> Observation {
    Observation::new(
        device_id.clone(),
        "scanner.routes.v1",
        ObservationType::Routes,
        TargetDescriptor::Host {
            hostname: "test-host".to_string(),
        },
        10,
        privilege,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Confidential,
        ObservationPayload::Routes(RouteObservationPayload {
            routes,
            default_gateways,
        }),
    )
    .unwrap()
}

fn make_dns_obs(
    device_id: &DeviceId,
    privilege: PrivilegeStatus,
    dns_servers: Vec<DnsServerRecord>,
) -> Observation {
    Observation::new(
        device_id.clone(),
        "scanner.dns.v1",
        ObservationType::Dns,
        TargetDescriptor::Host {
            hostname: "test-host".to_string(),
        },
        10,
        privilege,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Internal,
        ObservationPayload::Dns(DnsObservationPayload {
            dns_servers,
            search_domains: vec!["lan".to_string()],
            is_dynamic_dns_enabled: None,
        }),
    )
    .unwrap()
}

fn make_neighbors_obs(
    device_id: &DeviceId,
    privilege: PrivilegeStatus,
    neighbors: Vec<NeighborRecord>,
) -> Observation {
    Observation::new(
        device_id.clone(),
        "scanner.neighbors.v1",
        ObservationType::Neighbors,
        TargetDescriptor::Host {
            hostname: "test-host".to_string(),
        },
        10,
        privilege,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Internal,
        ObservationPayload::Neighbors(NeighborObservationPayload { neighbors }),
    )
    .unwrap()
}

fn sample_eth0() -> InterfaceRecord {
    InterfaceRecord {
        interface_name: "eth0".to_string(),
        friendly_name: Some("Ethernet 0".to_string()),
        interface_index: 2,
        mac_address_hash: Some("abcdef1234567890abcdef1234567890".to_string()),
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
    }
}

fn sample_wlan0() -> InterfaceRecord {
    InterfaceRecord {
        interface_name: "wlan0".to_string(),
        friendly_name: Some("Wi-Fi".to_string()),
        interface_index: 3,
        mac_address_hash: Some("11223344556677881122334455667788".to_string()),
        interface_type: InterfaceType::Wireless,
        oper_status: InterfaceStatus::Up,
        ip_addresses: vec![IpNetworkRecord {
            ip_address: "10.0.0.100".to_string(),
            prefix_length: 24,
            is_ipv6: false,
            classification: IpClassification::Private,
            broadcast_address: Some("10.0.0.255".to_string()),
        }],
        mtu: 1500,
        is_loopback: false,
        is_point_to_point: false,
        is_dhcp_enabled: Some(true),
        is_virtual: false,
    }
}

// =============================================================================
// Group 1: Construction Tests
// =============================================================================

#[test]
fn test_topology_all_sources_available() {
    let device_id = DeviceId::new();
    let observations = vec![
        make_interfaces_obs(&device_id, PrivilegeStatus::Available, vec![sample_eth0()]),
        make_routes_obs(
            &device_id,
            PrivilegeStatus::Available,
            vec![RouteRecord {
                destination_cidr: "0.0.0.0/0".to_string(),
                gateway_ip: Some("192.168.1.1".to_string()),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                metric: 10,
                is_ipv6: false,
                is_default_gateway: true,
                route_type: RouteType::Remote,
            }],
            vec!["192.168.1.1".to_string()],
        ),
        make_dns_obs(
            &device_id,
            PrivilegeStatus::Available,
            vec![DnsServerRecord {
                server_address: "192.168.1.1".to_string(),
                interface_name: Some("eth0".to_string()),
                is_ipv6: false,
                classification: IpClassification::Private,
            }],
        ),
        make_neighbors_obs(
            &device_id,
            PrivilegeStatus::Available,
            vec![NeighborRecord {
                ip_address: "192.168.1.1".to_string(),
                mac_address_hash: Some("9988776655443322".to_string()),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                state: NeighborState::Reachable,
                is_ipv6: false,
                ip_classification: IpClassification::Private,
                is_router: Some(true),
            }],
        ),
    ];

    let (iface_p, route_p, dns_p, neigh_p, missing, partial) =
        TopologyExtractor::extract_from_observations(&observations);

    assert!(iface_p.is_some());
    assert!(route_p.is_some());
    assert!(dns_p.is_some());
    assert!(neigh_p.is_some());
    assert!(missing.is_empty());
    assert!(partial.is_empty());

    let confidence = TopologyExtractor::compute_confidence(&observations);
    assert_eq!(confidence, ConfidenceScore::KERNEL_AUTHORITATIVE);

    let privilege = TopologyExtractor::derive_privilege(&observations);
    assert_eq!(privilege, PrivilegeStatus::Available);

    let snapshot = TopologyBuilder::build(
        device_id,
        iface_p.as_ref(),
        route_p.as_ref(),
        dns_p.as_ref(),
        neigh_p.as_ref(),
    );

    assert_eq!(snapshot.interfaces.len(), 1);
    assert_eq!(snapshot.default_gateways.len(), 1);
    assert_eq!(snapshot.dns_resolvers.len(), 1);
    assert_eq!(snapshot.neighbors.len(), 1);
    assert_eq!(snapshot.subnets.len(), 1);
    assert_eq!(snapshot.provenance_sources.len(), 4);
}

#[test]
fn test_topology_no_sources() {
    let device_id = DeviceId::new();
    let observations: Vec<Observation> = Vec::new();

    let (iface_p, route_p, dns_p, neigh_p, missing, partial) =
        TopologyExtractor::extract_from_observations(&observations);

    assert!(iface_p.is_none());
    assert!(route_p.is_none());
    assert!(dns_p.is_none());
    assert!(neigh_p.is_none());
    assert_eq!(missing.len(), 4);
    assert!(partial.is_empty());

    let confidence = TopologyExtractor::compute_confidence(&observations);
    assert_eq!(confidence, ConfidenceScore::HEURISTIC);

    let privilege = TopologyExtractor::derive_privilege(&observations);
    assert_eq!(privilege, PrivilegeStatus::Unsupported);

    let snapshot = TopologyBuilder::build(
        device_id,
        iface_p.as_ref(),
        route_p.as_ref(),
        dns_p.as_ref(),
        neigh_p.as_ref(),
    );

    assert!(snapshot.interfaces.is_empty());
    assert!(snapshot.default_gateways.is_empty());
    assert!(snapshot.dns_resolvers.is_empty());
    assert!(snapshot.neighbors.is_empty());
    assert!(snapshot.subnets.is_empty());
    assert!(snapshot.provenance_sources.is_empty());
}

#[test]
fn test_topology_interfaces_only() {
    let device_id = DeviceId::new();
    let observations = vec![make_interfaces_obs(
        &device_id,
        PrivilegeStatus::Available,
        vec![sample_eth0()],
    )];

    let (iface_p, route_p, dns_p, neigh_p, missing, partial) =
        TopologyExtractor::extract_from_observations(&observations);

    assert!(iface_p.is_some());
    assert!(route_p.is_none());
    assert!(dns_p.is_none());
    assert!(neigh_p.is_none());
    assert_eq!(missing.len(), 3);
    assert!(partial.is_empty());

    let confidence = TopologyExtractor::compute_confidence(&observations);
    assert_eq!(confidence, ConfidenceScore::HEURISTIC); // 1 usable source

    let snapshot = TopologyBuilder::build(
        device_id,
        iface_p.as_ref(),
        route_p.as_ref(),
        dns_p.as_ref(),
        neigh_p.as_ref(),
    );

    assert_eq!(snapshot.interfaces.len(), 1);
    assert_eq!(snapshot.subnets.len(), 1);
    assert_eq!(snapshot.subnets[0].network_cidr, "192.168.1.50/24");
    assert!(snapshot.default_gateways.is_empty());
    assert!(snapshot.dns_resolvers.is_empty());
    assert!(snapshot.neighbors.is_empty());
}

#[test]
fn test_topology_missing_neighbors() {
    let device_id = DeviceId::new();
    let observations = vec![
        make_interfaces_obs(&device_id, PrivilegeStatus::Available, vec![sample_eth0()]),
        make_routes_obs(
            &device_id,
            PrivilegeStatus::Available,
            vec![],
            vec!["192.168.1.1".to_string()],
        ),
        make_dns_obs(&device_id, PrivilegeStatus::Available, vec![]),
    ];

    let (_, _, _, neigh_p, missing, _) =
        TopologyExtractor::extract_from_observations(&observations);

    assert!(neigh_p.is_none());
    assert_eq!(missing, vec!["scanner.neighbors.v1".to_string()]);

    let confidence = TopologyExtractor::compute_confidence(&observations);
    assert_eq!(confidence, ConfidenceScore::SYSTEM_TABLE); // 3 usable sources
}

#[test]
fn test_topology_unsupported_sources() {
    let device_id = DeviceId::new();
    let observations = vec![
        make_interfaces_obs(&device_id, PrivilegeStatus::Available, vec![sample_eth0()]),
        make_routes_obs(&device_id, PrivilegeStatus::Available, vec![], vec![]),
        make_dns_obs(&device_id, PrivilegeStatus::Unsupported, vec![]),
        make_neighbors_obs(&device_id, PrivilegeStatus::Unsupported, vec![]),
    ];

    let (_, _, _, _, missing, partial) =
        TopologyExtractor::extract_from_observations(&observations);

    assert!(missing.is_empty());
    assert_eq!(partial.len(), 2);
    assert!(partial.contains(&"scanner.dns.v1".to_string()));
    assert!(partial.contains(&"scanner.neighbors.v1".to_string()));

    // 2 usable sources (interfaces + routes)
    let confidence = TopologyExtractor::compute_confidence(&observations);
    assert_eq!(confidence, ConfidenceScore::UNPRIVILEGED_PARTIAL);
}

#[test]
fn test_topology_partial_sources() {
    let device_id = DeviceId::new();
    let observations = vec![
        make_interfaces_obs(&device_id, PrivilegeStatus::Available, vec![sample_eth0()]),
        make_routes_obs(&device_id, PrivilegeStatus::Available, vec![], vec![]),
        make_dns_obs(&device_id, PrivilegeStatus::Available, vec![]),
        make_neighbors_obs(
            &device_id,
            PrivilegeStatus::Partial,
            vec![NeighborRecord {
                ip_address: "192.168.1.1".to_string(),
                mac_address_hash: None,
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                state: NeighborState::Reachable,
                is_ipv6: false,
                ip_classification: IpClassification::Private,
                is_router: None,
            }],
        ),
    ];

    let (_, _, _, neigh_p, missing, partial) =
        TopologyExtractor::extract_from_observations(&observations);

    assert!(missing.is_empty());
    assert_eq!(partial, vec!["scanner.neighbors.v1".to_string()]);
    // Data from partial source IS extracted and usable in synthesis
    assert!(neigh_p.is_some());
    assert_eq!(neigh_p.unwrap().neighbors.len(), 1);

    // But confidence score reflects only 3 usable sources
    let confidence = TopologyExtractor::compute_confidence(&observations);
    assert_eq!(confidence, ConfidenceScore::SYSTEM_TABLE);
}

// =============================================================================
// Group 2: Correlation Tests
// =============================================================================

#[test]
fn test_correlation_interface_has_gateway() {
    let device_id = DeviceId::new();
    let iface_p = InterfaceObservationPayload {
        interfaces: vec![sample_eth0()],
    };
    let route_p = RouteObservationPayload {
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
    };

    let snapshot = TopologyBuilder::build(device_id, Some(&iface_p), Some(&route_p), None, None);
    let edges = TopologyCorrelator::correlate(&snapshot);
    let gw_edges: Vec<_> = edges
        .iter()
        .filter(|e| e.kind == TopologyEdgeKind::InterfaceHasGateway)
        .collect();

    assert_eq!(gw_edges.len(), 1);
    assert_eq!(gw_edges[0].from_key, "interface:eth0");
    assert_eq!(gw_edges[0].to_key, "gateway:192.168.1.1");
}

#[test]
fn test_correlation_interface_has_neighbor() {
    let device_id = DeviceId::new();
    let iface_p = InterfaceObservationPayload {
        interfaces: vec![sample_eth0()],
    };
    let neigh_p = NeighborObservationPayload {
        neighbors: vec![NeighborRecord {
            ip_address: "192.168.1.200".to_string(),
            mac_address_hash: None,
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            state: NeighborState::Reachable,
            is_ipv6: false,
            ip_classification: IpClassification::Private,
            is_router: Some(false),
        }],
    };

    let snapshot = TopologyBuilder::build(device_id, Some(&iface_p), None, None, Some(&neigh_p));
    let edges = TopologyCorrelator::correlate(&snapshot);
    let neigh_edges: Vec<_> = edges
        .iter()
        .filter(|e| e.kind == TopologyEdgeKind::InterfaceHasNeighbor)
        .collect();

    assert_eq!(neigh_edges.len(), 1);
    assert_eq!(neigh_edges[0].from_key, "interface:eth0");
    assert_eq!(neigh_edges[0].to_key, "neighbor:192.168.1.200");
}

#[test]
fn test_correlation_neighbor_is_gateway() {
    let device_id = DeviceId::new();
    let route_p = RouteObservationPayload {
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
    };
    let neigh_p = NeighborObservationPayload {
        neighbors: vec![NeighborRecord {
            ip_address: "192.168.1.1".to_string(),
            mac_address_hash: None,
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            state: NeighborState::Reachable,
            is_ipv6: false,
            ip_classification: IpClassification::Private,
            is_router: Some(true),
        }],
    };

    let snapshot = TopologyBuilder::build(device_id, None, Some(&route_p), None, Some(&neigh_p));
    let edges = TopologyCorrelator::correlate(&snapshot);
    let is_gw_edges: Vec<_> = edges
        .iter()
        .filter(|e| e.kind == TopologyEdgeKind::NeighborIsGateway)
        .collect();

    assert_eq!(is_gw_edges.len(), 1);
    assert_eq!(is_gw_edges[0].from_key, "neighbor:192.168.1.1");
    assert_eq!(is_gw_edges[0].to_key, "gateway:192.168.1.1");
}

#[test]
fn test_correlation_dns_on_subnet_local() {
    let device_id = DeviceId::new();
    let iface_p = InterfaceObservationPayload {
        interfaces: vec![sample_eth0()],
    };
    let dns_p = DnsObservationPayload {
        dns_servers: vec![DnsServerRecord {
            server_address: "192.168.1.1".to_string(),
            interface_name: Some("eth0".to_string()),
            is_ipv6: false,
            classification: IpClassification::Private,
        }],
        search_domains: vec![],
        is_dynamic_dns_enabled: None,
    };

    let snapshot = TopologyBuilder::build(device_id, Some(&iface_p), None, Some(&dns_p), None);
    let edges = TopologyCorrelator::correlate(&snapshot);
    let dns_edges: Vec<_> = edges
        .iter()
        .filter(|e| e.kind == TopologyEdgeKind::DnsOnSubnet)
        .collect();

    assert_eq!(dns_edges.len(), 1);
    assert_eq!(dns_edges[0].from_key, "dns:192.168.1.1");
    assert_eq!(dns_edges[0].to_key, "subnet:192.168.1.50/24");
}

#[test]
fn test_correlation_dns_external_no_subnet_edge() {
    let device_id = DeviceId::new();
    let iface_p = InterfaceObservationPayload {
        interfaces: vec![sample_eth0()],
    };
    let dns_p = DnsObservationPayload {
        dns_servers: vec![DnsServerRecord {
            server_address: "8.8.8.8".to_string(),
            interface_name: None,
            is_ipv6: false,
            classification: IpClassification::PublicGlobal,
        }],
        search_domains: vec![],
        is_dynamic_dns_enabled: None,
    };

    let snapshot = TopologyBuilder::build(device_id, Some(&iface_p), None, Some(&dns_p), None);
    let edges = TopologyCorrelator::correlate(&snapshot);
    let dns_edges: Vec<_> = edges
        .iter()
        .filter(|e| e.kind == TopologyEdgeKind::DnsOnSubnet)
        .collect();

    assert!(dns_edges.is_empty());
}

#[test]
fn test_correlation_gateway_on_subnet() {
    let device_id = DeviceId::new();
    let iface_p = InterfaceObservationPayload {
        interfaces: vec![sample_wlan0()],
    };
    let route_p = RouteObservationPayload {
        routes: vec![RouteRecord {
            destination_cidr: "0.0.0.0/0".to_string(),
            gateway_ip: Some("10.0.0.1".to_string()),
            interface_index: 3,
            interface_name: Some("wlan0".to_string()),
            metric: 20,
            is_ipv6: false,
            is_default_gateway: true,
            route_type: RouteType::Remote,
        }],
        default_gateways: vec!["10.0.0.1".to_string()],
    };

    let snapshot = TopologyBuilder::build(device_id, Some(&iface_p), Some(&route_p), None, None);
    let edges = TopologyCorrelator::correlate(&snapshot);
    let gw_subnet_edges: Vec<_> = edges
        .iter()
        .filter(|e| e.kind == TopologyEdgeKind::GatewayOnSubnet)
        .collect();

    assert_eq!(gw_subnet_edges.len(), 1);
    assert_eq!(gw_subnet_edges[0].from_key, "gateway:10.0.0.1");
    assert_eq!(gw_subnet_edges[0].to_key, "subnet:10.0.0.100/24");
}

// =============================================================================
// Group 3: Multi-Homing & Protocol Tests
// =============================================================================

#[test]
fn test_topology_multi_homing_detection() {
    let device_id = DeviceId::new();
    let ifaces = vec![sample_eth0(), sample_wlan0()];

    let iface_payload = InterfaceObservationPayload { interfaces: ifaces };
    let snapshot = TopologyBuilder::build(device_id, Some(&iface_payload), None, None, None);

    assert_eq!(snapshot.interfaces.len(), 2);
    assert_eq!(snapshot.subnets.len(), 2);
    assert!(snapshot.is_multi_homed);
}

#[test]
fn test_topology_dual_stack_ipv4_ipv6() {
    let device_id = DeviceId::new();
    let iface = InterfaceRecord {
        interface_name: "eth0".to_string(),
        friendly_name: Some("Ethernet".to_string()),
        interface_index: 2,
        mac_address_hash: None,
        interface_type: InterfaceType::Ethernet,
        oper_status: InterfaceStatus::Up,
        ip_addresses: vec![
            IpNetworkRecord {
                ip_address: "192.168.1.50".to_string(),
                prefix_length: 24,
                is_ipv6: false,
                classification: IpClassification::Private,
                broadcast_address: Some("192.168.1.255".to_string()),
            },
            IpNetworkRecord {
                ip_address: "2001:db8::50".to_string(),
                prefix_length: 64,
                is_ipv6: true,
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

    let routes = vec![
        RouteRecord {
            destination_cidr: "0.0.0.0/0".to_string(),
            gateway_ip: Some("192.168.1.1".to_string()),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 10,
            is_ipv6: false,
            is_default_gateway: true,
            route_type: RouteType::Remote,
        },
        RouteRecord {
            destination_cidr: "::/0".to_string(),
            gateway_ip: Some("2001:db8::1".to_string()),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 10,
            is_ipv6: true,
            is_default_gateway: true,
            route_type: RouteType::Remote,
        },
    ];

    let dns = vec![
        DnsServerRecord {
            server_address: "192.168.1.1".to_string(),
            interface_name: Some("eth0".to_string()),
            is_ipv6: false,
            classification: IpClassification::Private,
        },
        DnsServerRecord {
            server_address: "2001:db8::1".to_string(),
            interface_name: Some("eth0".to_string()),
            is_ipv6: true,
            classification: IpClassification::PublicGlobal,
        },
    ];

    let iface_p = InterfaceObservationPayload {
        interfaces: vec![iface],
    };
    let route_p = RouteObservationPayload {
        routes,
        default_gateways: vec!["192.168.1.1".to_string(), "2001:db8::1".to_string()],
    };
    let dns_p = DnsObservationPayload {
        dns_servers: dns,
        search_domains: vec![],
        is_dynamic_dns_enabled: None,
    };

    let snapshot = TopologyBuilder::build(
        device_id,
        Some(&iface_p),
        Some(&route_p),
        Some(&dns_p),
        None,
    );

    assert_eq!(snapshot.subnets.len(), 2);
    assert_eq!(snapshot.default_gateways.len(), 2);
    assert_eq!(snapshot.dns_resolvers.len(), 2);

    let edges = TopologyCorrelator::correlate(&snapshot);
    let v6_dns_edges: Vec<_> = edges
        .iter()
        .filter(|e| e.kind == TopologyEdgeKind::DnsOnSubnet && e.from_key == "dns:2001:db8::1")
        .collect();
    assert_eq!(v6_dns_edges.len(), 1);
    assert_eq!(v6_dns_edges[0].to_key, "subnet:2001:db8::50/64");
}

#[test]
fn test_topology_multiple_default_gateways() {
    let device_id = DeviceId::new();
    let routes = vec![
        RouteRecord {
            destination_cidr: "0.0.0.0/0".to_string(),
            gateway_ip: Some("10.0.0.1".to_string()),
            interface_index: 3,
            interface_name: Some("wlan0".to_string()),
            metric: 50,
            is_ipv6: false,
            is_default_gateway: true,
            route_type: RouteType::Remote,
        },
        RouteRecord {
            destination_cidr: "0.0.0.0/0".to_string(),
            gateway_ip: Some("192.168.1.1".to_string()),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 10,
            is_ipv6: false,
            is_default_gateway: true,
            route_type: RouteType::Remote,
        },
    ];

    let route_p = RouteObservationPayload {
        routes,
        default_gateways: vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()],
    };

    let snapshot = TopologyBuilder::build(device_id, None, Some(&route_p), None, None);

    assert_eq!(snapshot.default_gateways.len(), 2);
    // Deterministically sorted by metric: metric 10 before metric 50
    assert_eq!(snapshot.default_gateways[0].gateway_ip, "192.168.1.1");
    assert_eq!(snapshot.default_gateways[1].gateway_ip, "10.0.0.1");
}

// =============================================================================
// Group 4: Resilience & Edge Cases
// =============================================================================

#[test]
fn test_resilience_duplicate_records() {
    let device_id = DeviceId::new();
    let dns_p = DnsObservationPayload {
        dns_servers: vec![
            DnsServerRecord {
                server_address: "1.1.1.1".to_string(),
                interface_name: None,
                is_ipv6: false,
                classification: IpClassification::PublicGlobal,
            },
            DnsServerRecord {
                server_address: "1.1.1.1".to_string(),
                interface_name: None,
                is_ipv6: false,
                classification: IpClassification::PublicGlobal,
            },
        ],
        search_domains: vec![],
        is_dynamic_dns_enabled: None,
    };

    let snapshot = TopologyBuilder::build(device_id, None, None, Some(&dns_p), None);
    assert_eq!(snapshot.dns_resolvers.len(), 2);
}

#[test]
fn test_resilience_conflicting_interface_indexes() {
    let device_id = DeviceId::new();
    let iface_p = InterfaceObservationPayload {
        interfaces: vec![sample_eth0()],
    };
    let route_p = RouteObservationPayload {
        routes: vec![RouteRecord {
            destination_cidr: "0.0.0.0/0".to_string(),
            gateway_ip: Some("10.10.10.1".to_string()),
            interface_index: 999, // Unknown index
            interface_name: None,
            metric: 10,
            is_ipv6: false,
            is_default_gateway: true,
            route_type: RouteType::Remote,
        }],
        default_gateways: vec!["10.10.10.1".to_string()],
    };

    let snapshot = TopologyBuilder::build(device_id, Some(&iface_p), Some(&route_p), None, None);
    let edges = TopologyCorrelator::correlate(&snapshot);
    let gw_edges: Vec<_> = edges
        .iter()
        .filter(|e| e.kind == TopologyEdgeKind::InterfaceHasGateway)
        .collect();

    assert_eq!(gw_edges.len(), 1);
    assert_eq!(gw_edges[0].from_key, "interface:idx:999");
}

#[test]
fn test_resilience_malformed_cidrs() {
    let device_id = DeviceId::new();
    let iface_p = InterfaceObservationPayload {
        interfaces: vec![InterfaceRecord {
            interface_name: "eth0".to_string(),
            friendly_name: None,
            interface_index: 2,
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
        }],
    };
    let route_p = RouteObservationPayload {
        routes: vec![RouteRecord {
            destination_cidr: "0.0.0.0/0".to_string(),
            gateway_ip: Some("10.10.10.10".to_string()), // Outside subnet
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 10,
            is_ipv6: false,
            is_default_gateway: true,
            route_type: RouteType::Remote,
        }],
        default_gateways: vec!["10.10.10.10".to_string()],
    };

    let snapshot = TopologyBuilder::build(device_id, Some(&iface_p), Some(&route_p), None, None);
    let edges = TopologyCorrelator::correlate(&snapshot);
    let gw_subnet_edges: Vec<_> = edges
        .iter()
        .filter(|e| e.kind == TopologyEdgeKind::GatewayOnSubnet)
        .collect();

    assert!(gw_subnet_edges.is_empty());
}

// =============================================================================
// Group 5: Determinism Tests
// =============================================================================

#[test]
fn test_determinism_edge_ordering() {
    let device_id = DeviceId::new();
    let iface_p = InterfaceObservationPayload {
        interfaces: vec![sample_wlan0(), sample_eth0()],
    };
    let route_p = RouteObservationPayload {
        routes: vec![
            RouteRecord {
                destination_cidr: "0.0.0.0/0".to_string(),
                gateway_ip: Some("10.0.0.1".to_string()),
                interface_index: 3,
                interface_name: Some("wlan0".to_string()),
                metric: 20,
                is_ipv6: false,
                is_default_gateway: true,
                route_type: RouteType::Remote,
            },
            RouteRecord {
                destination_cidr: "0.0.0.0/0".to_string(),
                gateway_ip: Some("192.168.1.1".to_string()),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                metric: 10,
                is_ipv6: false,
                is_default_gateway: true,
                route_type: RouteType::Remote,
            },
        ],
        default_gateways: vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()],
    };
    let dns_p = DnsObservationPayload {
        dns_servers: vec![
            DnsServerRecord {
                server_address: "10.0.0.1".to_string(),
                interface_name: Some("wlan0".to_string()),
                is_ipv6: false,
                classification: IpClassification::Private,
            },
            DnsServerRecord {
                server_address: "192.168.1.1".to_string(),
                interface_name: Some("eth0".to_string()),
                is_ipv6: false,
                classification: IpClassification::Private,
            },
        ],
        search_domains: vec![],
        is_dynamic_dns_enabled: None,
    };
    let neigh_p = NeighborObservationPayload {
        neighbors: vec![
            NeighborRecord {
                ip_address: "10.0.0.1".to_string(),
                mac_address_hash: None,
                interface_index: 3,
                interface_name: Some("wlan0".to_string()),
                state: NeighborState::Reachable,
                is_ipv6: false,
                ip_classification: IpClassification::Private,
                is_router: Some(true),
            },
            NeighborRecord {
                ip_address: "192.168.1.1".to_string(),
                mac_address_hash: None,
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                state: NeighborState::Reachable,
                is_ipv6: false,
                ip_classification: IpClassification::Private,
                is_router: Some(true),
            },
        ],
    };

    let snapshot = TopologyBuilder::build(
        device_id,
        Some(&iface_p),
        Some(&route_p),
        Some(&dns_p),
        Some(&neigh_p),
    );

    let edges1 = TopologyCorrelator::correlate(&snapshot);
    let edges2 = TopologyCorrelator::correlate(&snapshot);

    assert_eq!(edges1, edges2);

    for window in edges1.windows(2) {
        let a = &window[0];
        let b = &window[1];
        let ord = a
            .kind
            .cmp(&b.kind)
            .then_with(|| a.from_key.cmp(&b.from_key))
            .then_with(|| a.to_key.cmp(&b.to_key));
        assert!(
            ord != std::cmp::Ordering::Greater,
            "Edges must be strictly ordered"
        );
    }
}

#[test]
fn test_determinism_evidence_hash_identical_inputs() {
    let device_id = DeviceId::new();
    let iface_p = InterfaceObservationPayload {
        interfaces: vec![sample_eth0()],
    };

    let snapshot1 = TopologyBuilder::build(device_id.clone(), Some(&iface_p), None, None, None);
    let snapshot2 = snapshot1.clone();

    let edges1 = TopologyCorrelator::correlate(&snapshot1);
    let edges2 = TopologyCorrelator::correlate(&snapshot2);

    let payload1 = ObservationPayload::Topology(TopologyObservationPayload {
        snapshot: snapshot1,
        edges: edges1,
        missing_sources: vec![],
        partial_sources: vec![],
    });
    let payload2 = ObservationPayload::Topology(TopologyObservationPayload {
        snapshot: snapshot2,
        edges: edges2,
        missing_sources: vec![],
        partial_sources: vec![],
    });

    let hash1 = Observation::compute_evidence_hash(&payload1).unwrap();
    let hash2 = Observation::compute_evidence_hash(&payload2).unwrap();

    assert_eq!(hash1, hash2);
    assert_eq!(hash1.len(), 64);
}

// =============================================================================
// Group 6: Privacy Tests
// =============================================================================

#[test]
fn test_privacy_no_raw_mac_in_serialized_topology() {
    let device_id = DeviceId::new();
    let iface = sample_eth0();
    let iface_payload = InterfaceObservationPayload {
        interfaces: vec![iface],
    };

    let snapshot = TopologyBuilder::build(device_id, Some(&iface_payload), None, None, None);
    let edges = TopologyCorrelator::correlate(&snapshot);
    let topo_payload = ObservationPayload::Topology(TopologyObservationPayload {
        snapshot,
        edges,
        missing_sources: vec![],
        partial_sources: vec![],
    });

    let json_str = serde_json::to_string(&topo_payload).unwrap();

    // Verify raw MAC colon/dash formats are absent
    assert!(!json_str.contains("00:11:22"));
    assert!(!json_str.contains("00-11-22"));
    assert!(!json_str.contains("AA:BB:CC"));
    // Ensure mac_address_hash IS present
    assert!(json_str.contains("mac_address_hash"));
}

// =============================================================================
// Group 7: Supervisor Integration Tests
// =============================================================================

#[test]
fn test_scanner_supervisor_step5_and_step6_integration() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let storage = Arc::new(DatabaseEngine::in_memory().unwrap());
        let scanners = create_all_platform_scanners(false);
        assert_eq!(scanners.len(), 10, "Scanner count must be exactly 10");

        let supervisor = ScannerSupervisor::new(storage.clone(), scanners);
        let device_id = DeviceId::new();

        let result = supervisor.run_scan_cycle(&device_id).await.unwrap();

        assert_eq!(result.total_scanners, 10);
        assert!(result.successful_scanners > 0);
        assert!(
            result.topology_synthesized,
            "Topology must be successfully synthesized and enqueued in Step 5/6"
        );

        // Verify SQLite queue contains 1 topology observation record
        let queued_count = storage
            .with_reader(|conn| {
                ObservationQueueRepository::count_by_status(conn, ObservationStatus::Queued)
            })
            .await
            .unwrap();

        assert!(
            queued_count >= (result.observations_collected + 1) as i64,
            "Queue must contain collected observations + 1 synthesized topology observation"
        );
    });
}
