//! # Comprehensive CLI Integration Tests (`cli_tests.rs`)

use std::fs;
use tempfile::tempdir;

use netra_cli::cli::{CheckArgs, RecoverArgs, StorageSubcommand};
use netra_cli::commands;
use netra_cli::errors::ExitCode;
use netra_cli::output::OutputPresenter;
use netra_core::config::NetraConfig;
use netra_core::runtime::RuntimeCoordinator;
use netra_core::storage::DatabaseEngine;
use netra_core::ComponentLifecycle;
use netra_platform::create_platform_adapter;

#[tokio::test]
async fn test_status_command_execution() {
    let coordinator = RuntimeCoordinator::new();
    let adapter = create_platform_adapter();
    coordinator.register_component(adapter).await.unwrap();
    coordinator.initialize().await.unwrap();
    coordinator.start().await.unwrap();

    let presenter = OutputPresenter::new(true, true, true);
    let code = commands::status::execute(&coordinator, None, &presenter)
        .await
        .unwrap();

    assert_eq!(code, ExitCode::Success);
    let _ = coordinator.shutdown().await;
}

#[tokio::test]
async fn test_diagnostics_command_execution() {
    let coordinator = RuntimeCoordinator::new();
    let config = NetraConfig::default();
    let presenter = OutputPresenter::new(true, true, true);

    let code = commands::diagnostics::execute(&config, &coordinator, None, &presenter)
        .await
        .unwrap();

    assert_eq!(code, ExitCode::Success);
}

#[tokio::test]
async fn test_storage_status_and_check_execution() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("agent.db");

    let mut config = NetraConfig::default();
    config.storage.db_path = db_path.clone();

    let storage_engine = DatabaseEngine::new(&config.storage);
    storage_engine.initialize().await.unwrap();
    storage_engine.start().await.unwrap();

    let presenter = OutputPresenter::new(true, true, true);

    // 1. Storage Status
    let code = commands::storage::execute(
        &StorageSubcommand::Status,
        &config,
        Some(&storage_engine),
        &presenter,
    )
    .await
    .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 2. Storage Check (Tier 2 quick_check)
    let check_args = CheckArgs { deep: false };
    let code = commands::storage::execute(
        &StorageSubcommand::Check(check_args),
        &config,
        Some(&storage_engine),
        &presenter,
    )
    .await
    .unwrap();
    assert_eq!(code, ExitCode::Success);

    // 3. Storage Check (Tier 3 deep check)
    let deep_check_args = CheckArgs { deep: true };
    let code = commands::storage::execute(
        &StorageSubcommand::Check(deep_check_args),
        &config,
        Some(&storage_engine),
        &presenter,
    )
    .await
    .unwrap();
    assert_eq!(code, ExitCode::Success);

    let _ = storage_engine.stop().await;
}

#[tokio::test]
async fn test_storage_recover_force_reinit_flow() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("agent.db");

    // Write dummy/corrupted database content
    fs::write(&db_path, b"CORRUPTED_SQLITE_DATA").unwrap();

    let mut config = NetraConfig::default();
    config.storage.db_path = db_path.clone();

    let presenter = OutputPresenter::new(true, true, true);

    // 1. Storage check fails on corrupted database
    let check_args = CheckArgs { deep: false };
    let check_code = commands::storage::execute(
        &StorageSubcommand::Check(check_args),
        &config,
        None,
        &presenter,
    )
    .await
    .unwrap();
    assert_eq!(check_code, ExitCode::DegradedState);

    // 2. Storage recover without --force-reinit in non-interactive environment is refused
    let unforced_args = RecoverArgs {
        force_reinit: false,
    };
    let unforced_code = commands::storage::execute(
        &StorageSubcommand::Recover(unforced_args),
        &config,
        None,
        &presenter,
    )
    .await
    .unwrap();
    assert_eq!(unforced_code, ExitCode::OperationalError);

    // 3. Storage recover WITH --force-reinit succeeds, quarantines corrupt file, and reinitializes
    let forced_args = RecoverArgs { force_reinit: true };
    let forced_code = commands::storage::execute(
        &StorageSubcommand::Recover(forced_args),
        &config,
        None,
        &presenter,
    )
    .await
    .unwrap();
    assert_eq!(forced_code, ExitCode::Success);

    // 4. Verify fresh database is healthy
    let check_args = CheckArgs { deep: false };
    let check_code = commands::storage::execute(
        &StorageSubcommand::Check(check_args),
        &config,
        None,
        &presenter,
    )
    .await
    .unwrap();
    assert_eq!(check_code, ExitCode::Success);

    // 5. Verify quarantine directory exists and contains metadata
    let parent = db_path.parent().unwrap();
    let mut quarantine_found = false;
    for entry in fs::read_dir(parent).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("quarantine_") {
            quarantine_found = true;
            assert!(entry.path().join("quarantine_meta.json").exists());
            break;
        }
    }
    assert!(quarantine_found, "Quarantine directory must be preserved");
}
