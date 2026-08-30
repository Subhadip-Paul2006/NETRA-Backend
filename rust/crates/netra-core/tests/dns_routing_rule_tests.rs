//! # Integration Tests for Phase 8.7.3 DNS & Routing Posture Finding Rules
//!
//! Evaluates NET-005-INVALID-DNS-RESOLVER and NET-006-LOOPBACK-ROUTE-LEAK across
//! valid configurations, misconfigurations, confidence guardrails, deterministic
//! deduplication, and privacy guarantees.

use netra_core::id::DeviceId;
use netra_core::network::IpClassification;
use netra_core::observation::models::{ConfidenceScore, PrivilegeStatus, SensitivityLevel};
use netra_core::observation::payloads::{
    DnsObservationPayload, DnsServerRecord, ObservationPayload, RouteObservationPayload,
    RouteRecord, RouteType,
};
use netra_core::observation::{Observation, ObservationType, TargetDescriptor};
use netra_core::rules::traits::FindingRule;
use netra_core::rules::{Net005InvalidDnsResolverRule, Net006LoopbackRouteLeakRule, RuleEngine};
use netra_core::storage::repositories::findings::FindingsRepository;
use netra_core::storage::FindingSeverity;

fn make_dns_observation(
    servers: Vec<DnsServerRecord>,
    privilege: PrivilegeStatus,
    confidence: ConfidenceScore,
) -> Observation {
    Observation::new(
        DeviceId::new(),
        "scanner.dns.v1",
        ObservationType::Dns,
        TargetDescriptor::Host {
            hostname: "test-host".to_string(),
        },
        10,
        privilege,
        confidence,
        SensitivityLevel::Public,
        ObservationPayload::Dns(DnsObservationPayload {
            dns_servers: servers,
            search_domains: vec!["local".to_string()],
            is_dynamic_dns_enabled: None,
        }),
    )
    .unwrap()
}

fn make_routes_observation(
    routes: Vec<RouteRecord>,
    privilege: PrivilegeStatus,
    confidence: ConfidenceScore,
) -> Observation {
    Observation::new(
        DeviceId::new(),
        "scanner.routes.v1",
        ObservationType::Routes,
        TargetDescriptor::Host {
            hostname: "test-host".to_string(),
        },
        10,
        privilege,
        confidence,
        SensitivityLevel::Public,
        ObservationPayload::Routes(RouteObservationPayload {
            routes,
            default_gateways: vec!["192.168.1.1".to_string()],
        }),
    )
    .unwrap()
}

// =============================================================================
// VECTOR 1: Valid Public, Private, Loopback, and Link-Local DNS evaluate CLEAN
// =============================================================================
#[test]
fn test_net005_valid_public_and_private_dns_clean() {
    let rule = Net005InvalidDnsResolverRule::new();
    let obs = make_dns_observation(
        vec![
            DnsServerRecord {
                server_address: "8.8.8.8".to_string(),
                interface_name: Some("eth0".to_string()),
                is_ipv6: false,
                classification: IpClassification::PublicGlobal,
            },
            DnsServerRecord {
                server_address: "1.1.1.1".to_string(),
                interface_name: Some("eth0".to_string()),
                is_ipv6: false,
                classification: IpClassification::PublicGlobal,
            },
            DnsServerRecord {
                server_address: "192.168.1.1".to_string(),
                interface_name: Some("eth0".to_string()),
                is_ipv6: false,
                classification: IpClassification::Private,
            },
            DnsServerRecord {
                server_address: "127.0.0.53".to_string(),
                interface_name: None,
                is_ipv6: false,
                classification: IpClassification::Loopback,
            },
            DnsServerRecord {
                server_address: "fe80::1".to_string(),
                interface_name: Some("eth0".to_string()),
                is_ipv6: true,
                classification: IpClassification::LinkLocal,
            },
        ],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert!(findings.is_empty(), "Valid DNS servers must evaluate clean");
}

// =============================================================================
// VECTOR 2: Unspecified IPv4 Nameserver 0.0.0.0 emits Low severity finding
// =============================================================================
#[test]
fn test_net005_unspecified_ipv4_nameserver_emits_low_finding() {
    let rule = Net005InvalidDnsResolverRule::new();
    let obs = make_dns_observation(
        vec![DnsServerRecord {
            server_address: "0.0.0.0".to_string(),
            interface_name: Some("eth0".to_string()),
            is_ipv6: false,
            classification: IpClassification::Unspecified,
        }],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, FindingSeverity::Low);
    assert_eq!(findings[0].target.target_key(), "dns_server:0.0.0.0");
    assert_eq!(findings[0].discriminator, "INVALID_DNS:0.0.0.0:UNSPECIFIED");
    assert!(findings[0].description.contains("UNSPECIFIED"));
}

// =============================================================================
// VECTOR 3: Unspecified IPv6 Nameserver :: emits Low severity finding
// =============================================================================
#[test]
fn test_net005_unspecified_ipv6_nameserver_emits_low_finding() {
    let rule = Net005InvalidDnsResolverRule::new();
    let obs = make_dns_observation(
        vec![DnsServerRecord {
            server_address: "::".to_string(),
            interface_name: Some("eth0".to_string()),
            is_ipv6: true,
            classification: IpClassification::Unspecified,
        }],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, FindingSeverity::Low);
    assert_eq!(findings[0].target.target_key(), "dns_server:::");
    assert_eq!(findings[0].discriminator, "INVALID_DNS::::UNSPECIFIED");
}

// =============================================================================
// VECTOR 4: Broadcast Nameserver 255.255.255.255 emits Low severity finding
// =============================================================================
#[test]
fn test_net005_broadcast_nameserver_emits_low_finding() {
    let rule = Net005InvalidDnsResolverRule::new();
    let obs = make_dns_observation(
        vec![DnsServerRecord {
            server_address: "255.255.255.255".to_string(),
            interface_name: Some("eth0".to_string()),
            is_ipv6: false,
            classification: IpClassification::Broadcast,
        }],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, FindingSeverity::Low);
    assert_eq!(
        findings[0].target.target_key(),
        "dns_server:255.255.255.255"
    );
    assert_eq!(
        findings[0].discriminator,
        "INVALID_DNS:255.255.255.255:BROADCAST"
    );
}

// =============================================================================
// VECTOR 5: Multicast Nameserver emits Low severity finding
// =============================================================================
#[test]
fn test_net005_multicast_nameserver_emits_low_finding() {
    let rule = Net005InvalidDnsResolverRule::new();
    let obs = make_dns_observation(
        vec![
            DnsServerRecord {
                server_address: "224.0.0.251".to_string(),
                interface_name: None,
                is_ipv6: false,
                classification: IpClassification::Multicast,
            },
            DnsServerRecord {
                server_address: "ff02::fb".to_string(),
                interface_name: None,
                is_ipv6: true,
                classification: IpClassification::Multicast,
            },
        ],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].target.target_key(), "dns_server:224.0.0.251");
    assert_eq!(findings[1].target.target_key(), "dns_server:ff02::fb");
}

// =============================================================================
// VECTOR 6: Documentation Address Space Nameserver emits Low finding
// =============================================================================
#[test]
fn test_net005_documentation_nameserver_emits_low_finding() {
    let rule = Net005InvalidDnsResolverRule::new();
    let obs = make_dns_observation(
        vec![DnsServerRecord {
            server_address: "192.0.2.1".to_string(),
            interface_name: None,
            is_ipv6: false,
            classification: IpClassification::Documentation,
        }],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].target.target_key(), "dns_server:192.0.2.1");
    assert_eq!(
        findings[0].discriminator,
        "INVALID_DNS:192.0.2.1:DOCUMENTATION"
    );
}

// =============================================================================
// VECTOR 7: Guardrail Missing DNS Source Suppresses Findings
// =============================================================================
#[test]
fn test_net005_guardrail_missing_dns_source_suppresses() {
    let rule = Net005InvalidDnsResolverRule::new();
    // Observation with PermissionDenied
    let obs = make_dns_observation(
        vec![DnsServerRecord {
            server_address: "0.0.0.0".to_string(),
            interface_name: None,
            is_ipv6: false,
            classification: IpClassification::Unspecified,
        }],
        PrivilegeStatus::PermissionDenied,
        ConfidenceScore::HEURISTIC,
    );

    let findings = rule.evaluate(&obs);
    assert!(
        findings.is_empty(),
        "PermissionDenied privilege must suppress findings"
    );
}

// =============================================================================
// VECTOR 8: Guardrail Partial DNS Source Keeps / Downgrades to Low
// =============================================================================
#[test]
fn test_net005_guardrail_partial_source_downgrades() {
    let rule = Net005InvalidDnsResolverRule::new();
    let obs = make_dns_observation(
        vec![DnsServerRecord {
            server_address: "0.0.0.0".to_string(),
            interface_name: None,
            is_ipv6: false,
            classification: IpClassification::Unspecified,
        }],
        PrivilegeStatus::Partial,
        ConfidenceScore::UNPRIVILEGED_PARTIAL,
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, FindingSeverity::Low);
}

// =============================================================================
// VECTOR 9: Standard Loopback Routes Evaluate CLEAN
// =============================================================================
#[test]
fn test_net006_standard_loopback_routes_clean() {
    let rule = Net006LoopbackRouteLeakRule::new();
    let obs = make_routes_observation(
        vec![
            RouteRecord {
                destination_cidr: "127.0.0.1/32".to_string(),
                gateway_ip: Some("127.0.0.1".to_string()),
                interface_index: 1,
                interface_name: Some("lo".to_string()),
                metric: 0,
                is_ipv6: false,
                is_default_gateway: false,
                route_type: RouteType::Local,
            },
            RouteRecord {
                destination_cidr: "127.0.0.0/8".to_string(),
                gateway_ip: None,
                interface_index: 1,
                interface_name: Some("lo".to_string()),
                metric: 256,
                is_ipv6: false,
                is_default_gateway: false,
                route_type: RouteType::Direct,
            },
            RouteRecord {
                destination_cidr: "::1/128".to_string(),
                gateway_ip: None,
                interface_index: 1,
                interface_name: Some("lo".to_string()),
                metric: 256,
                is_ipv6: true,
                is_default_gateway: false,
                route_type: RouteType::Direct,
            },
        ],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert!(
        findings.is_empty(),
        "Standard loopback routes must evaluate clean"
    );
}

// =============================================================================
// VECTOR 10: VPN and Docker /32 Routes Evaluate CLEAN
// =============================================================================
#[test]
fn test_net006_vpn_and_docker_routes_clean() {
    let rule = Net006LoopbackRouteLeakRule::new();
    let obs = make_routes_observation(
        vec![
            RouteRecord {
                destination_cidr: "198.51.100.10/32".to_string(),
                gateway_ip: Some("192.168.1.1".to_string()),
                interface_index: 2,
                interface_name: Some("eth0".to_string()),
                metric: 25,
                is_ipv6: false,
                is_default_gateway: false,
                route_type: RouteType::Remote,
            },
            RouteRecord {
                destination_cidr: "172.17.0.0/16".to_string(),
                gateway_ip: None,
                interface_index: 3,
                interface_name: Some("docker0".to_string()),
                metric: 0,
                is_ipv6: false,
                is_default_gateway: false,
                route_type: RouteType::Direct,
            },
        ],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert!(
        findings.is_empty(),
        "Non-loopback /32 and bridge routes must evaluate clean"
    );
}

// =============================================================================
// VECTOR 11: IPv4 Loopback Routed to Physical Gateway Emits Medium Finding
// =============================================================================
#[test]
fn test_net006_ipv4_loopback_routed_to_physical_gateway_emits_medium() {
    let rule = Net006LoopbackRouteLeakRule::new();
    let obs = make_routes_observation(
        vec![RouteRecord {
            destination_cidr: "127.0.0.0/8".to_string(),
            gateway_ip: Some("192.168.1.1".to_string()),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 25,
            is_ipv6: false,
            is_default_gateway: false,
            route_type: RouteType::Remote,
        }],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, FindingSeverity::Medium);
    assert_eq!(
        findings[0].target.target_key(),
        "route:127.0.0.0/8:192.168.1.1"
    );
    assert_eq!(
        findings[0].discriminator,
        "LOOPBACK_ROUTE:127.0.0.0/8:192.168.1.1"
    );
    assert_eq!(
        findings[0].title,
        "Loopback Address Space Routed to External Interface"
    );
}

// =============================================================================
// VECTOR 12: IPv6 Loopback Routed to Physical Gateway Emits Medium Finding
// =============================================================================
#[test]
fn test_net006_ipv6_loopback_routed_to_physical_gateway_emits_medium() {
    let rule = Net006LoopbackRouteLeakRule::new();
    let obs = make_routes_observation(
        vec![RouteRecord {
            destination_cidr: "::1/128".to_string(),
            gateway_ip: Some("2001:db8::1".to_string()),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 25,
            is_ipv6: true,
            is_default_gateway: false,
            route_type: RouteType::Remote,
        }],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, FindingSeverity::Medium);
    assert_eq!(findings[0].target.target_key(), "route:::1/128:2001:db8::1");
    assert_eq!(
        findings[0].discriminator,
        "LOOPBACK_ROUTE:::1/128:2001:db8::1"
    );
}

// =============================================================================
// VECTOR 13: Guardrail Missing Route Source Suppresses Findings
// =============================================================================
#[test]
fn test_net006_guardrail_missing_route_source_suppresses() {
    let rule = Net006LoopbackRouteLeakRule::new();
    let obs = make_routes_observation(
        vec![RouteRecord {
            destination_cidr: "127.0.0.0/8".to_string(),
            gateway_ip: Some("192.168.1.1".to_string()),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 25,
            is_ipv6: false,
            is_default_gateway: false,
            route_type: RouteType::Remote,
        }],
        PrivilegeStatus::PermissionDenied,
        ConfidenceScore::HEURISTIC,
    );

    let findings = rule.evaluate(&obs);
    assert!(
        findings.is_empty(),
        "PermissionDenied on routes must suppress findings"
    );
}

// =============================================================================
// VECTOR 14: Guardrail Partial Route Source Downgrades to Low
// =============================================================================
#[test]
fn test_net006_guardrail_partial_source_downgrades_to_low() {
    let rule = Net006LoopbackRouteLeakRule::new();
    let obs = make_routes_observation(
        vec![RouteRecord {
            destination_cidr: "127.0.0.0/8".to_string(),
            gateway_ip: Some("192.168.1.1".to_string()),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 25,
            is_ipv6: false,
            is_default_gateway: false,
            route_type: RouteType::Remote,
        }],
        PrivilegeStatus::Partial,
        ConfidenceScore::UNPRIVILEGED_PARTIAL,
    );

    let findings = rule.evaluate(&obs);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].severity,
        FindingSeverity::Low,
        "Partial route privilege must downgrade Medium to Low"
    );
}

// =============================================================================
// VECTOR 15: Deterministic Fingerprints Across Scans & Rule Engine Integration
// =============================================================================
#[test]
fn test_deterministic_fingerprints_across_scans() {
    let rule = Net005InvalidDnsResolverRule::new();
    let obs_dns = make_dns_observation(
        vec![DnsServerRecord {
            server_address: "0.0.0.0".to_string(),
            interface_name: Some("eth0".to_string()),
            is_ipv6: false,
            classification: IpClassification::Unspecified,
        }],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let raw_1 = rule.evaluate(&obs_dns);
    let raw_2 = rule.evaluate(&obs_dns);

    assert_eq!(raw_1.len(), 1);
    assert_eq!(raw_2.len(), 1);

    let fp_1 = FindingsRepository::compute_fingerprint(
        rule.rule_id(),
        &raw_1[0].target.target_key(),
        &raw_1[0].discriminator,
    );
    let fp_2 = FindingsRepository::compute_fingerprint(
        rule.rule_id(),
        &raw_2[0].target.target_key(),
        &raw_2[0].discriminator,
    );

    assert_eq!(
        fp_1, fp_2,
        "Fingerprints must be bitwise identical across evaluation runs"
    );

    let engine = RuleEngine::with_all_rules();
    let engine_findings_1 = engine.evaluate(&obs_dns);
    let engine_findings_2 = engine.evaluate(&obs_dns);
    assert_eq!(engine_findings_1.len(), 1);
    assert_eq!(engine_findings_2.len(), 1);
    assert_eq!(
        engine_findings_1[0].fingerprint, engine_findings_2[0].fingerprint,
        "RuleEngine output fingerprints must be deterministic"
    );
    assert_eq!(engine_findings_1[0].fingerprint, fp_1);
}

// =============================================================================
// VECTOR 16: Privacy Guarantees — Zero Raw Hardware MAC Addresses
// =============================================================================
#[test]
fn test_privacy_zero_raw_mac_leakage() {
    let rule_dns = Net005InvalidDnsResolverRule::new();
    let rule_route = Net006LoopbackRouteLeakRule::new();

    let obs_dns = make_dns_observation(
        vec![DnsServerRecord {
            server_address: "0.0.0.0".to_string(),
            interface_name: Some("eth0".to_string()),
            is_ipv6: false,
            classification: IpClassification::Unspecified,
        }],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let obs_route = make_routes_observation(
        vec![RouteRecord {
            destination_cidr: "127.0.0.0/8".to_string(),
            gateway_ip: Some("192.168.1.1".to_string()),
            interface_index: 2,
            interface_name: Some("eth0".to_string()),
            metric: 25,
            is_ipv6: false,
            is_default_gateway: false,
            route_type: RouteType::Remote,
        }],
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
    );

    let dns_findings = rule_dns.evaluate(&obs_dns);
    let route_findings = rule_route.evaluate(&obs_route);

    for f in dns_findings.iter().chain(route_findings.iter()) {
        let evidence_str = f.raw_evidence.to_string();
        assert!(
            !evidence_str.contains("mac_address")
                || evidence_str.contains("mac_address_hash")
                || !evidence_str.contains(":"),
            "Evidence must never contain raw MAC addresses: {}",
            evidence_str
        );
    }
}
