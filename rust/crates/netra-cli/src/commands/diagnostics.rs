//! # `netra diagnostics` Command Handler (`netra-cli::commands::diagnostics`)
//!
//! Generates a local diagnostic bundle containing environment, platform, configuration,
//! and storage integrity information.

use serde::Serialize;
use std::path::PathBuf;

use netra_core::config::NetraConfig;
use netra_core::runtime::RuntimeCoordinator;
use netra_core::storage::{DatabaseEngine, StorageState};
use netra_platform::{detect_platform_info, PlatformInfo};

use crate::errors::{CliError, ExitCode};
use crate::output::formatting::format_box_block;
use crate::output::OutputPresenter;
use crate::version::NETRA_VERSION;

/// Payload model for `netra diagnostics`.
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticsData {
    pub platform: PlatformInfo,
    pub runtime_state: String,
    pub runtime_health: String,
    pub config_valid: bool,
    pub db_path: PathBuf,
    pub db_exists: bool,
    pub storage_state: String,
}

/// Executes the `netra diagnostics` command.
pub async fn execute(
    config: &NetraConfig,
    coordinator: &RuntimeCoordinator,
    storage: Option<&DatabaseEngine>,
    presenter: &OutputPresenter,
) -> Result<ExitCode, CliError> {
    let platform = detect_platform_info();
    let state = coordinator.state().await;
    let health = coordinator.health().await;
    let config_valid = config.validate().is_ok();
    let db_path = config.storage.db_path.clone();
    let db_exists = db_path.exists();

    let storage_state_str = if let Some(eng) = storage {
        match eng.state() {
            StorageState::Uninitialized => "UNINITIALIZED".to_string(),
            StorageState::Ready => "READY".to_string(),
            StorageState::Degraded(r) => format!("DEGRADED: {r}"),
            StorageState::Stopping => "STOPPING".to_string(),
            StorageState::Stopped => "STOPPED".to_string(),
            StorageState::Failed(r) => format!("FAILED: {r}"),
        }
    } else {
        "NOT_INITIALIZED".to_string()
    };

    let data = DiagnosticsData {
        platform: platform.clone(),
        runtime_state: state.to_string(),
        runtime_health: health.to_string(),
        config_valid,
        db_path: db_path.clone(),
        db_exists,
        storage_state: storage_state_str.clone(),
    };

    let title = format!("NETRA Environment Diagnostics Bundle (v{NETRA_VERSION})");
    presenter.emit_result("diagnostics", &data, |c| {
        let priv_str = if platform.is_elevated {
            c.yellow("ELEVATED")
        } else {
            c.cyan("STANDARD_USER")
        };

        let cfg_str = if config_valid {
            c.green("VALID")
        } else {
            c.red("INVALID")
        };

        let db_str = if db_exists {
            c.green(&format!("PRESENT ({})", db_path.display()))
        } else {
            c.yellow(&format!("ABSENT ({})", db_path.display()))
        };

        format_box_block(
            &title,
            &[
                (
                    "Platform",
                    format!("{} ({})", platform.os_family, platform.os_version),
                ),
                ("Architecture", platform.arch),
                ("Hostname", platform.hostname),
                ("Privilege", priv_str),
                ("Runtime State", c.green(&state.to_string())),
                ("Runtime Health", c.green(&health.to_string())),
                ("Config Validation", cfg_str),
                ("Database File", db_str),
                ("Storage State", c.green(&storage_state_str)),
            ],
            c,
        )
    });

    Ok(ExitCode::Success)
}
