use netra_cli::cli::{FindingsArgs, FindingsListArgs, FindingsSubcommand, ScanArgs};
use netra_cli::commands::findings::execute_findings;
use netra_cli::commands::scan::execute_scan;
use netra_cli::errors::ExitCode;
use netra_cli::output::OutputPresenter;
use netra_core::config::NetraConfig;
use netra_core::storage::DatabaseEngine;

#[tokio::test]
async fn test_scan_and_findings_cli_pipeline() {
    let engine = DatabaseEngine::in_memory().unwrap();
    let config = NetraConfig::default();
    let presenter = OutputPresenter::new(true, true, true); // JSON mode

    // 1. Execute full scan
    let scan_args = ScanArgs {
        domain: None,
        hash_binaries: false,
    };
    let scan_exit = execute_scan(&scan_args, &config, Some(&engine), &presenter)
        .await
        .unwrap();

    // On Windows, if open ports or disabled firewalls exist, exit code might be PolicyFailure (2) or Success (0)
    assert!(
        scan_exit == ExitCode::Success || scan_exit == ExitCode::PolicyFailure,
        "Expected Success or PolicyFailure, got {:?}",
        scan_exit
    );

    // 2. Execute single domain scan (sockets)
    let socket_scan_args = ScanArgs {
        domain: Some("sockets".to_string()),
        hash_binaries: false,
    };
    let socket_exit = execute_scan(&socket_scan_args, &config, Some(&engine), &presenter)
        .await
        .unwrap();
    assert!(
        socket_exit == ExitCode::Success || socket_exit == ExitCode::PolicyFailure,
        "Expected Success or PolicyFailure, got {:?}",
        socket_exit
    );

    // 3. Query findings via CLI
    let findings_args = FindingsArgs {
        action: Some(FindingsSubcommand::List(FindingsListArgs::default())),
    };
    let findings_exit = execute_findings(&findings_args, &config, Some(&engine), &presenter)
        .await
        .unwrap();
    assert_eq!(findings_exit, ExitCode::Success);
}
