use netra_core::id::DeviceId;
use netra_core::observation::{
    ConfidenceScore, FirewallObservationPayload, FirewallProfileRecord, Observation,
    ObservationPayload, ObservationType, PrivilegeStatus, SensitivityLevel,
    SocketObservationPayload, SocketProtocol, SocketRecord, TargetDescriptor,
};

#[test]
fn test_all_target_descriptors_and_keys() {
    let host = TargetDescriptor::Host {
        hostname: "WORKSTATION-01".to_string(),
    };
    assert_eq!(host.target_key(), "host:workstation-01");

    let proc = TargetDescriptor::Process {
        pid: 2048,
        executable_path: Some("C:\\Windows\\System32\\svchost.exe".to_string()),
    };
    assert_eq!(proc.target_key(), "process:2048");

    let sock = TargetDescriptor::Socket {
        protocol: SocketProtocol::Tcp,
        port: 8080,
        bind_address: "0.0.0.0".to_string(),
    };
    assert_eq!(sock.target_key(), "socket:tcp:0.0.0.0:8080");

    let fw = TargetDescriptor::Firewall {
        profile: "Public".to_string(),
    };
    assert_eq!(fw.target_key(), "firewall:public");

    let user = TargetDescriptor::User {
        username: "Guest".to_string(),
        uid_or_sid: Some("S-1-5-32-546".to_string()),
    };
    assert_eq!(user.target_key(), "user:guest");

    let svc = TargetDescriptor::Service {
        service_name: "Spooler".to_string(),
    };
    assert_eq!(svc.target_key(), "service:spooler");

    let os = TargetDescriptor::OsConfiguration {
        check_name: "SecureBoot".to_string(),
    };
    assert_eq!(os.target_key(), "os_config:secureboot");
}

#[test]
fn test_canonical_evidence_hash_determinism() {
    let payload = ObservationPayload::Sockets(SocketObservationPayload {
        sockets: vec![
            SocketRecord {
                protocol: SocketProtocol::Tcp,
                local_address: "0.0.0.0".to_string(),
                local_port: 80,
                remote_address: None,
                remote_port: None,
                state: "LISTEN".to_string(),
                owning_pid: 100,
                process_name: Some("httpd".to_string()),
            },
            SocketRecord {
                protocol: SocketProtocol::Udp,
                local_address: "127.0.0.1".to_string(),
                local_port: 5353,
                remote_address: None,
                remote_port: None,
                state: "BOUND".to_string(),
                owning_pid: 200,
                process_name: None,
            },
        ],
    });

    let hash1 = Observation::compute_evidence_hash(&payload).unwrap();
    let hash2 = Observation::compute_evidence_hash(&payload).unwrap();
    assert_eq!(hash1, hash2);
    assert_eq!(hash1.len(), 64);
}

#[test]
fn test_observation_envelope_structure() {
    let device_id = DeviceId::new();
    let payload = ObservationPayload::Firewall(FirewallObservationPayload {
        profiles: vec![FirewallProfileRecord {
            profile_name: "Domain".to_string(),
            is_enabled: true,
            default_inbound_action: "Block".to_string(),
            default_outbound_action: "Allow".to_string(),
            active_rules_count: 42,
        }],
    });

    let obs = Observation::new(
        device_id.clone(),
        "scanner.firewall.v1",
        ObservationType::Firewall,
        TargetDescriptor::Firewall {
            profile: "Domain".to_string(),
        },
        50,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Confidential,
        payload,
    )
    .unwrap();

    assert_eq!(obs.schema_version, 1);
    assert_eq!(obs.device_id, device_id);
    assert_eq!(obs.privilege_level, PrivilegeStatus::Available);
    assert_eq!(obs.sensitivity, SensitivityLevel::Confidential);
    assert_eq!(obs.duration_ms, 50);

    let json = serde_json::to_string(&obs).unwrap();
    let deserialized: Observation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, deserialized);
}
