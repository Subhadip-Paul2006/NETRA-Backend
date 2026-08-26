//! # Command Dispatcher (`netra-cli::commands`)
//!
//! Routes parsed CLI commands to dedicated handler implementations.

pub mod diagnostics;
pub mod identity;
pub mod status;
pub mod storage;

use netra_core::config::NetraConfig;
use netra_core::runtime::RuntimeCoordinator;
use netra_core::storage::DatabaseEngine;

use crate::cli::{CliArgs, Commands};
use crate::errors::{CliError, ExitCode};
use crate::output::formatting::format_box_block;
use crate::output::OutputPresenter;
use crate::version::VersionInfo;

/// Dispatches a parsed command to its appropriate handler.
pub async fn dispatch(
    args: &CliArgs,
    config: &NetraConfig,
    coordinator: &RuntimeCoordinator,
    storage: Option<&DatabaseEngine>,
    presenter: &OutputPresenter,
) -> Result<ExitCode, CliError> {
    match &args.command {
        None | Some(Commands::Status) => status::execute(coordinator, storage, presenter).await,
        Some(Commands::Diagnostics) => {
            diagnostics::execute(config, coordinator, storage, presenter).await
        }
        Some(Commands::Storage(s_args)) => {
            storage::execute(&s_args.action, config, storage, presenter).await
        }
        Some(Commands::Enroll(e_args)) => {
            identity::execute_enroll(e_args, config, storage, presenter).await
        }
        Some(Commands::Identity(i_args)) => {
            identity::execute_identity(i_args, config, storage, presenter).await
        }
        Some(Commands::Version) => {
            let info = VersionInfo::current();
            let title = "NETRA Version & Build Information";
            presenter.emit_result("version", &info, |c| {
                format_box_block(
                    title,
                    &[
                        ("Schema Version", info.schema_version.to_string()),
                        ("NETRA Version", info.netra_version.to_string()),
                        ("Target OS", info.target_os.to_string()),
                        ("Target Architecture", info.target_arch.to_string()),
                        ("Build Profile", info.profile.to_string()),
                        ("License", info.license.to_string()),
                    ],
                    c,
                )
            });
            Ok(ExitCode::Success)
        }
    }
}
