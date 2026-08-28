use netra_core::id::DeviceId;
use netra_core::observation::{
    ConfidenceScore, FirewallObservationPayload, FirewallProfileRecord, Observation,
    ObservationPayload, ObservationType, OsConfigObservationPayload, OsConfigRecord,
    PrivilegeStatus, SensitivityLevel, ServiceObservationPayload, ServiceRecord, ServiceStartType,
    ServiceState, SocketObservationPayload, SocketProtocol, SocketRecord, TargetDescriptor,
    UserObservationPayload, UserRecord,
};
use netra_core::rules::RuleEngine;
use netra_core::storage::repositories::findings::FindingsRepository;
use netra_core::storage::repositories::queue::ObservationQueueRepository;
use netra_core::storage::{DatabaseEngine, FindingSeverity, FindingStatus, ObservationStatus};

#[tokio::test]
async fn test_full_pipeline_rule_evaluation_and_sqlite_persistence() {
    let engine = DatabaseEngine::in_memory().unwrap();
    let rule_engine = RuleEngine::with_baseline_rules();
    let device_id = DeviceId::new();

    // 1. Create a simulated observation with plaintext port and unrestricted database
    let payload = ObservationPayload::Sockets(SocketObservationPayload {
        sockets: vec![
            SocketRecord {
                protocol: SocketProtocol::Tcp,
                local_address: "0.0.0.0".to_string(),
                local_port: 80,
                remote_address: None,
                remote_port: None,
                state: "LISTEN".to_string(),
                owning_pid: 101,
                process_name: Some("httpd".to_string()),
            },
            SocketRecord {
                protocol: SocketProtocol::Tcp,
                local_address: "0.0.0.0".to_string(),
                local_port: 5432,
                remote_address: None,
                remote_port: None,
                state: "LISTEN".to_string(),
                owning_pid: 102,
                process_name: Some("postgres".to_string()),
            },
        ],
    });

    let obs = Observation::new(
        device_id.clone(),
        "scanner.sockets.v1",
        ObservationType::Sockets,
        TargetDescriptor::Host {
            hostname: "localhost".to_string(),
        },
        20,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Public,
        payload.clone(),
    )
    .unwrap();

    // 2. Enqueue into SQLite observation_queue
    let payload_str = serde_json::to_string(&obs.payload).unwrap();
    let obs_type = format!("{:?}", obs.observation_type).to_lowercase();
    let queued = engine
        .with_writer(move |conn| {
            ObservationQueueRepository::enqueue(conn, &obs_type, &payload_str, None)
        })
        .await
        .unwrap();

    assert_eq!(queued.status, ObservationStatus::Queued);
    assert!(!queued.sha256_hash.is_empty());

    // 3. Evaluate observation against RuleEngine
    let findings = rule_engine.evaluate(&obs);
    assert_eq!(findings.len(), 2);

    // 4. Upsert findings into local_findings table
    for finding in &findings {
        let f_rule = finding.rule_id.clone();
        let f_sev = finding.severity;
        let f_title = finding.title.clone();
        let f_ev = finding.evidence_summary_json.clone();

        // Extract target and discriminator from evidence_summary_json
        let parsed: serde_json::Value = serde_json::from_str(&f_ev).unwrap();
        let target_key = parsed["target_key"].as_str().unwrap_or("").to_string();

        let upsert_res = engine
            .with_writer(move |conn| {
                FindingsRepository::upsert(
                    conn,
                    &f_rule,
                    f_sev,
                    &target_key,
                    "test_disc",
                    &f_title,
                    &f_ev,
                )
            })
            .await
            .unwrap();

        assert_eq!(upsert_res.occurrence_count, 1);
        assert_eq!(upsert_res.status, FindingStatus::Open);
    }

    // 5. Query active findings
    let all_findings = engine
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .unwrap();
    assert_eq!(all_findings.len(), 2);

    // 6. Test deduplication / recurrence
    let first_finding = &findings[0];
    let f_rule2 = first_finding.rule_id.clone();
    let f_sev2 = first_finding.severity;
    let f_title2 = first_finding.title.clone();
    let f_ev2 = first_finding.evidence_summary_json.clone();
    let parsed2: serde_json::Value = serde_json::from_str(&f_ev2).unwrap();
    let target_key2 = parsed2["target_key"].as_str().unwrap_or("").to_string();

    let recurrence_res = engine
        .with_writer(move |conn| {
            FindingsRepository::upsert(
                conn,
                &f_rule2,
                f_sev2,
                &target_key2,
                "test_disc",
                &f_title2,
                &f_ev2,
            )
        })
        .await
        .unwrap();

    assert_eq!(recurrence_res.occurrence_count, 2);
}

#[test]
fn test_all_baseline_rules_evaluation() {
    let rule_engine = RuleEngine::with_baseline_rules();
    let device_id = DeviceId::new();

    // Firewall rule test
    let fw_obs = Observation::new(
        device_id.clone(),
        "scanner.firewall.v1",
        ObservationType::Firewall,
        TargetDescriptor::Firewall {
            profile: "Public".to_string(),
        },
        10,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Confidential,
        ObservationPayload::Firewall(FirewallObservationPayload {
            profiles: vec![FirewallProfileRecord {
                profile_name: "Public".to_string(),
                is_enabled: false,
                default_inbound_action: "Block".to_string(),
                default_outbound_action: "Allow".to_string(),
                active_rules_count: 0,
            }],
        }),
    )
    .unwrap();
    let fw_findings = rule_engine.evaluate(&fw_obs);
    assert_eq!(fw_findings.len(), 1);
    assert_eq!(fw_findings[0].rule_id, "FW-001-PROFILE-DISABLED");
    assert_eq!(fw_findings[0].severity, FindingSeverity::Critical);

    // User rule test
    let user_obs = Observation::new(
        device_id.clone(),
        "scanner.users.v1",
        ObservationType::Users,
        TargetDescriptor::User {
            username: "Guest".to_string(),
            uid_or_sid: Some("S-1-5-32-546".to_string()),
        },
        10,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Internal,
        ObservationPayload::Users(UserObservationPayload {
            users: vec![UserRecord {
                username: "Guest".to_string(),
                uid_or_sid: "S-1-5-32-546".to_string(),
                is_enabled: true,
                is_admin: false,
                account_type: "Local".to_string(),
                last_logon_timestamp: None,
            }],
        }),
    )
    .unwrap();
    let user_findings = rule_engine.evaluate(&user_obs);
    assert_eq!(user_findings.len(), 1);
    assert_eq!(user_findings[0].rule_id, "USR-001-GUEST-ENABLED");
    assert_eq!(user_findings[0].severity, FindingSeverity::Medium);

    // Service rule test
    let svc_obs = Observation::new(
        device_id.clone(),
        "scanner.services.v1",
        ObservationType::Services,
        TargetDescriptor::Service {
            service_name: "InsecureSvc".to_string(),
        },
        10,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Internal,
        ObservationPayload::Services(ServiceObservationPayload {
            services: vec![ServiceRecord {
                service_name: "InsecureSvc".to_string(),
                display_name: "Insecure Service".to_string(),
                state: ServiceState::Running,
                start_type: ServiceStartType::Auto,
                binary_path: Some("C:\\Program Files\\Insecure Service\\service.exe".to_string()),
                account_context: Some("LocalSystem".to_string()),
            }],
        }),
    )
    .unwrap();
    let svc_findings = rule_engine.evaluate(&svc_obs);
    assert_eq!(svc_findings.len(), 1);
    assert_eq!(svc_findings[0].rule_id, "SVC-001-UNQUOTED-PATH");
    assert_eq!(svc_findings[0].severity, FindingSeverity::Low);

    // OS Security rule test
    let os_obs = Observation::new(
        device_id.clone(),
        "scanner.os.v1",
        ObservationType::OsConfig,
        TargetDescriptor::OsConfiguration {
            check_name: "SecureBoot".to_string(),
        },
        10,
        PrivilegeStatus::Available,
        ConfidenceScore::KERNEL_AUTHORITATIVE,
        SensitivityLevel::Internal,
        ObservationPayload::OsConfig(OsConfigObservationPayload {
            configurations: vec![OsConfigRecord {
                check_name: "SecureBoot".to_string(),
                status: "FAIL".to_string(),
                value: "0".to_string(),
                details: Some("UEFI Secure Boot is disabled".to_string()),
            }],
        }),
    )
    .unwrap();
    let os_findings = rule_engine.evaluate(&os_obs);
    assert_eq!(os_findings.len(), 1);
    assert_eq!(os_findings[0].rule_id, "OS-001-SECUREBOOT-OFF");
    assert_eq!(os_findings[0].severity, FindingSeverity::High);
}
