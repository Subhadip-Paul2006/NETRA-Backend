//! # Comprehensive Findings CLI Integration Tests (`findings_cli_tests.rs`)
//!
//! Verifies `netra findings list`, `netra findings show`, and `netra findings count`
//! subcommands, argument validation, error semantics, and output rendering.

use chrono::Utc;
use netra_cli::cli::{
    FindingsArgs, FindingsCountArgs, FindingsListArgs, FindingsShowArgs, FindingsSubcommand,
};
use netra_cli::commands::findings::execute_findings;
use netra_cli::errors::ExitCode;
use netra_cli::output::OutputPresenter;
use netra_core::config::NetraConfig;
use netra_core::storage::{
    DatabaseEngine, FindingEntry, FindingSeverity, FindingStatus, FindingsRepository,
};

/// Helper to initialize an in-memory database engine and seed test findings.
async fn setup_test_engine_with_findings() -> (DatabaseEngine, Vec<FindingEntry>) {
    let engine = DatabaseEngine::in_memory().unwrap();

    let entries = vec![
        FindingEntry {
            fingerprint: "1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            rule_id: "NET-003-GATEWAY-OFF-SUBNET".to_string(),
            severity: FindingSeverity::Medium,
            status: FindingStatus::Open,
            title: "Gateway IP Not Present on Interface Subnet".to_string(),
            evidence_summary_json: serde_json::json!({
                "target_key": "network_gateway:2:192.168.1.1",
                "reason": "Gateway not in subnet",
                "remediation": "Update gateway address",
                "gateway_ip": "192.168.1.1"
            })
            .to_string(),
            occurrence_count: 2,
            first_seen: Utc::now().to_rfc3339(),
            last_seen: Utc::now().to_rfc3339(),
        },
        FindingEntry {
            fingerprint: "2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            rule_id: "NET-005-INVALID-DNS-RESOLVER".to_string(),
            severity: FindingSeverity::Low,
            status: FindingStatus::Resolved,
            title: "Unroutable DNS Resolver Address".to_string(),
            evidence_summary_json: serde_json::json!({
                "target_key": "dns:0.0.0.0",
                "reason": "Unspecified address 0.0.0.0",
                "remediation": "Remove 0.0.0.0 resolver"
            })
            .to_string(),
            occurrence_count: 1,
            first_seen: Utc::now().to_rfc3339(),
            last_seen: Utc::now().to_rfc3339(),
        },
        FindingEntry {
            fingerprint: "3333333333333333333333333333333333333333333333333333333333333333"
                .to_string(),
            rule_id: "NET-002-UNRESTRICTED-DB".to_string(),
            severity: FindingSeverity::Critical,
            status: FindingStatus::Open,
            title: "Database Listening on 0.0.0.0".to_string(),
            evidence_summary_json: serde_json::json!({
                "target_key": "socket:0.0.0.0:5432",
                "reason": "Unrestricted PostgreSQL listener",
                "remediation": "Bind to 127.0.0.1"
            })
            .to_string(),
            occurrence_count: 5,
            first_seen: Utc::now().to_rfc3339(),
            last_seen: Utc::now().to_rfc3339(),
        },
        FindingEntry {
            fingerprint: "4444444444444444444444444444444444444444444444444444444444444444"
                .to_string(),
            rule_id: "FW-001-PROFILE-DISABLED".to_string(),
            severity: FindingSeverity::High,
            status: FindingStatus::Suppressed,
            title: "Host Firewall Profile Disabled".to_string(),
            evidence_summary_json: serde_json::json!({
                "target_key": "firewall:public",
                "reason": "Public firewall profile is inactive",
                "remediation": "Enable public profile"
            })
            .to_string(),
            occurrence_count: 1,
            first_seen: Utc::now().to_rfc3339(),
            last_seen: Utc::now().to_rfc3339(),
        },
    ];

    let entries_clone = entries.clone();
    engine
        .with_writer(move |conn| {
            for entry in &entries_clone {
                FindingsRepository::upsert_entry(conn, entry)?;
            }
            FindingsRepository::resolve(
                conn,
                "2222222222222222222222222222222222222222222222222222222222222222",
            )?;
            FindingsRepository::suppress(
                conn,
                "4444444444444444444444444444444444444444444444444444444444444444",
            )?;
            Ok(())
        })
        .await
        .unwrap();

    (engine, entries)
}

#[tokio::test]
async fn test_cli_findings_list_flow() {
    let (engine, _) = setup_test_engine_with_findings().await;
    let config = NetraConfig::default();
    let presenter_human = OutputPresenter::new(false, true, true);
    let presenter_json = OutputPresenter::new(true, true, true);

    // 1. Default list (Human Mode)
    let args = FindingsArgs { action: None };
    let code = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 2. Default list (JSON Mode)
    let code = execute_findings(&args, &config, Some(&engine), &presenter_json)
        .await
        .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 3. Filter by status: OPEN
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::List(FindingsListArgs {
            status: Some("OPEN".to_string()),
            ..Default::default()
        })),
    };
    let code = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 4. Filter by severity: CRITICAL
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::List(FindingsListArgs {
            severity: Some("CRITICAL".to_string()),
            ..Default::default()
        })),
    };
    let code = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 5. Filter by canonical short rule: NET-003
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::List(FindingsListArgs {
            rule: Some("NET-003".to_string()),
            ..Default::default()
        })),
    };
    let code = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 6. Filter by full rule: NET-003-GATEWAY-OFF-SUBNET
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::List(FindingsListArgs {
            rule: Some("NET-003-GATEWAY-OFF-SUBNET".to_string()),
            ..Default::default()
        })),
    };
    let code = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 7. Filter with limit: 1
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::List(FindingsListArgs {
            limit: Some(1),
            ..Default::default()
        })),
    };
    let code = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 8. Invalid status -> InvalidArguments
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::List(FindingsListArgs {
            status: Some("INVALID_STATUS".to_string()),
            ..Default::default()
        })),
    };
    let err = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap_err();
    assert_eq!(err.exit_code, ExitCode::InvalidArguments);

    // 9. Invalid severity -> InvalidArguments
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::List(FindingsListArgs {
            severity: Some("SUPER_HIGH".to_string()),
            ..Default::default()
        })),
    };
    let err = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap_err();
    assert_eq!(err.exit_code, ExitCode::InvalidArguments);

    // 10. Prohibited arbitrary partial rule -> InvalidArguments
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::List(FindingsListArgs {
            rule: Some("NET-00".to_string()),
            ..Default::default()
        })),
    };
    let err = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap_err();
    assert_eq!(err.exit_code, ExitCode::InvalidArguments);

    // 11. Limit 0 -> InvalidArguments
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::List(FindingsListArgs {
            limit: Some(0),
            ..Default::default()
        })),
    };
    let err = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap_err();
    assert_eq!(err.exit_code, ExitCode::InvalidArguments);
}

#[tokio::test]
async fn test_cli_findings_show_flow() {
    let (engine, _) = setup_test_engine_with_findings().await;
    let config = NetraConfig::default();
    let presenter_human = OutputPresenter::new(false, true, true);
    let presenter_json = OutputPresenter::new(true, true, true);

    let valid_fp = "1111111111111111111111111111111111111111111111111111111111111111";

    // 1. Existing finding (Human Mode)
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::Show(FindingsShowArgs {
            fingerprint: valid_fp.to_string(),
        })),
    };
    let code = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 2. Existing finding (JSON Mode)
    let code = execute_findings(&args, &config, Some(&engine), &presenter_json)
        .await
        .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 3. Valid 64-character hex fingerprint but non-existent in database -> NotFound / InvalidArguments (exit code 3)
    let missing_fp = "9999999999999999999999999999999999999999999999999999999999999999";
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::Show(FindingsShowArgs {
            fingerprint: missing_fp.to_string(),
        })),
    };
    let err = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap_err();
    assert_eq!(err.exit_code, ExitCode::InvalidArguments);
    assert_eq!(err.code, "ERR_NOT_FOUND");
    assert!(err.message.contains("not found"));

    // 4. Malformed fingerprints -> InvalidArguments (exit code 3)
    let malformed_cases = vec![
        "short_fp",
        "1111",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // non-hex
        "111111111111111111111111111111111111111111111111111111111111111",  // 63 chars
        "11111111111111111111111111111111111111111111111111111111111111111", // 65 chars
    ];

    for bad_fp in malformed_cases {
        let args = FindingsArgs {
            action: Some(FindingsSubcommand::Show(FindingsShowArgs {
                fingerprint: bad_fp.to_string(),
            })),
        };
        let err = execute_findings(&args, &config, Some(&engine), &presenter_human)
            .await
            .unwrap_err();
        assert_eq!(err.exit_code, ExitCode::InvalidArguments);
        assert_eq!(err.code, "ERR_INVALID_ARGUMENTS");
        assert!(err.message.contains("64-character hexadecimal"));
    }
}

#[tokio::test]
async fn test_cli_findings_count_flow() {
    let (engine, _) = setup_test_engine_with_findings().await;
    let config = NetraConfig::default();
    let presenter_human = OutputPresenter::new(false, true, true);
    let presenter_json = OutputPresenter::new(true, true, true);

    // 1. Unfiltered count (Human & JSON)
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::Count(FindingsCountArgs::default())),
    };
    let code = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap();
    assert_eq!(code, ExitCode::Success);

    let code = execute_findings(&args, &config, Some(&engine), &presenter_json)
        .await
        .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 2. Count with status: OPEN
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::Count(FindingsCountArgs {
            status: Some("OPEN".to_string()),
            ..Default::default()
        })),
    };
    let code = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 3. Count with severity: CRITICAL
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::Count(FindingsCountArgs {
            severity: Some("CRITICAL".to_string()),
            ..Default::default()
        })),
    };
    let code = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 4. Count with canonical short rule: NET-005
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::Count(FindingsCountArgs {
            rule: Some("NET-005".to_string()),
            ..Default::default()
        })),
    };
    let code = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 5. Count with invalid status -> InvalidArguments
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::Count(FindingsCountArgs {
            status: Some("BOGUS".to_string()),
            ..Default::default()
        })),
    };
    let err = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap_err();
    assert_eq!(err.exit_code, ExitCode::InvalidArguments);

    // 6. Count with invalid severity -> InvalidArguments
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::Count(FindingsCountArgs {
            severity: Some("BOGUS".to_string()),
            ..Default::default()
        })),
    };
    let err = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap_err();
    assert_eq!(err.exit_code, ExitCode::InvalidArguments);

    // 7. Count with invalid rule -> InvalidArguments
    let args = FindingsArgs {
        action: Some(FindingsSubcommand::Count(FindingsCountArgs {
            rule: Some("NET-999".to_string()),
            ..Default::default()
        })),
    };
    let err = execute_findings(&args, &config, Some(&engine), &presenter_human)
        .await
        .unwrap_err();
    assert_eq!(err.exit_code, ExitCode::InvalidArguments);
}
