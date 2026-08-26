//! # `netra status` Command Handler (`netra-cli::commands::status`)
//!
//! Queries runtime coordinator state, host platform details, and storage health.

use serde::Serialize;

use netra_core::runtime::RuntimeCoordinator;
use netra_core::storage::{DatabaseEngine, StorageState};
use netra_platform::{detect_platform_info, PlatformInfo};

use crate::errors::{CliError, ExitCode};
use crate::output::formatting::format_box_block;
use crate::output::OutputPresenter;
use crate::version::NETRA_VERSION;

/// Payload model for `netra status`.
#[derive(Debug, Clone, Serialize)]
pub struct StatusData {
    pub platform: PlatformInfo,
    pub runtime_state: String,
    pub runtime_health: String,
    pub storage_state: String,
}

/// Executes the `netra status` command.
pub async fn execute(
    coordinator: &RuntimeCoordinator,
    storage: Option<&DatabaseEngine>,
    presenter: &OutputPresenter,
) -> Result<ExitCode, CliError> {
    let platform = detect_platform_info();
    let state = coordinator.state().await;
    let health = coordinator.health().await;

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

    let data = StatusData {
        platform: platform.clone(),
        runtime_state: state.to_string(),
        runtime_health: health.to_string(),
        storage_state: storage_state_str.clone(),
    };

    let exit_code = if matches!(storage.map(|s| s.state()), Some(StorageState::Degraded(_))) {
        ExitCode::DegradedState
    } else {
        ExitCode::Success
    };

    let title = format!("NETRA Host Security Agent (v{NETRA_VERSION})");
    presenter.emit_result("status", &data, |c| {
        let priv_str = if platform.is_elevated {
            c.yellow("ELEVATED (Administrator)")
        } else {
            c.cyan("STANDARD_USER")
        };

        let state_colored = if state.is_terminal() {
            c.red(&state.to_string())
        } else {
            c.green(&format!("● {state}"))
        };

        let health_colored = if matches!(health, netra_core::runtime::ComponentHealth::Healthy) {
            c.green(&format!("● {health}"))
        } else {
            c.yellow(&format!("▲ {health}"))
        };

        let storage_colored = if storage_state_str.starts_with("READY") {
            c.green(&format!("● {storage_state_str}"))
        } else {
            c.yellow(&format!("▲ {storage_state_str}"))
        };

        format_box_block(
            &title,
            &[
                (
                    "Platform",
                    format!(
                        "{} ({}) [{}]",
                        platform.os_family, platform.arch, platform.hostname
                    ),
                ),
                ("OS Version", platform.os_version),
                ("Privilege", priv_str),
                ("Runtime State", state_colored),
                ("Runtime Health", health_colored),
                ("Storage Engine", storage_colored),
            ],
            c,
        )
    });

    Ok(exit_code)
}
