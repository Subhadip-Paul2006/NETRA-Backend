//! # NETRA CLI (`netra-cli`)
//!
//! **Command-Line Interface & Diagnostic Tool for NETRA**
//!
//! `netra-cli` provides the user-facing CLI binary (`netra`) implementing the Unix
//! philosophy of canonical stream separation:
//!
//! - **Standard Output (`stdout`)**: Exclusively reserved for primary command results (human formatted or pure JSON).
//! - **Standard Error (`stderr`)**: Reserved for human diagnostic output, ANSI formatting, progress banners, warnings, and error messages.
//! - **Standard Exit Codes**: `0` (Success), `1` (Operational Error), `2` (Policy Violation), `3` (Invalid Arguments), `4` (Degraded State).

use std::process::ExitCode as StdExitCode;
use std::sync::Arc;

use clap::Parser;

use netra_cli::cli::{self, CliArgs};
use netra_cli::commands;
use netra_cli::errors::{CliError, ExitCode};
use netra_cli::output::OutputPresenter;
use netra_core::config::NetraConfig;
use netra_core::logging::init_logging;
use netra_core::runtime::RuntimeCoordinator;
use netra_core::storage::DatabaseEngine;
use netra_platform::create_platform_adapter;

#[tokio::main]
async fn main() -> StdExitCode {
    let args = match CliArgs::try_parse() {
        Ok(a) => a,
        Err(err) => {
            // Clap handles --help and --version with exit code 0 automatically
            let _ = err.print();
            let code = if err.use_stderr() {
                ExitCode::InvalidArguments
            } else {
                ExitCode::Success
            };
            return code.into();
        }
    };

    let presenter = OutputPresenter::new(args.json, args.quiet, args.no_color);

    // 1. Initialize configuration (CLI Flags > Environment Variables > TOML File > Defaults)
    let mut config = if let Some(path) = &args.config {
        match NetraConfig::from_file(path) {
            Ok(cfg) => cfg,
            Err(err) => {
                let cli_err = CliError::from(err);
                presenter.emit_error("config", &cli_err);
                return cli_err.exit_code.into();
            }
        }
    } else {
        NetraConfig::default()
    };

    config.apply_env_overrides();

    // 2. Initialize structured logging
    if let Err(err) = init_logging(&config.logging) {
        let cli_err = CliError::from(err);
        presenter.emit_error("logging", &cli_err);
        return cli_err.exit_code.into();
    }

    // 3. Handle worker launcher mode immediately if --worker flag passed
    if args.worker {
        let token = args
            .ipc_token
            .clone()
            .or_else(|| std::env::var("NETRA_IPC_TOKEN").ok())
            .unwrap_or_default();
        return run_worker_process(token).await.into();
    }

    // 4. Initialize RuntimeCoordinator and components
    let coordinator = RuntimeCoordinator::new();
    let platform_adapter = create_platform_adapter();

    if let Err(err) = coordinator.register_component(platform_adapter).await {
        let cli_err = CliError::from(err);
        presenter.emit_error("runtime_registration", &cli_err);
        return cli_err.exit_code.into();
    }

    // 5. Initialize Storage Engine
    let storage_engine = Arc::new(DatabaseEngine::new(&config.storage));
    if let Err(err) = coordinator.register_component(storage_engine.clone()).await {
        let cli_err = CliError::from(err);
        presenter.emit_error("storage_registration", &cli_err);
        return cli_err.exit_code.into();
    }

    if let Err(err) = coordinator.initialize().await {
        let cli_err = CliError::from(err);
        presenter.emit_error("runtime_init", &cli_err);
        return cli_err.exit_code.into();
    }

    if let Err(err) = coordinator.start().await {
        let cli_err = CliError::from(err);
        presenter.emit_error("runtime_start", &cli_err);
        return cli_err.exit_code.into();
    }

    // 6. Dispatch command
    let code = match commands::dispatch(
        &args,
        &config,
        &coordinator,
        Some(&storage_engine),
        &presenter,
    )
    .await
    {
        Ok(code) => code,
        Err(err) => {
            let cmd_name = match &args.command {
                None | Some(cli::Commands::Status) => "status",
                Some(cli::Commands::Diagnostics) => "diagnostics",
                Some(cli::Commands::Storage(_)) => "storage",
                Some(cli::Commands::Version) => "version",
            };
            presenter.emit_error(cmd_name, &err);
            err.exit_code
        }
    };

    // 7. Graceful reverse teardown of runtime
    let _ = coordinator.shutdown().await;

    code.into()
}

async fn run_worker_process(token: String) -> ExitCode {
    use netra_core::worker::WorkerHarness;
    use netra_platform::create_ipc_client;

    let harness = WorkerHarness::new(token);
    let client = match create_ipc_client(None) {
        Ok(c) => c,
        Err(_) => return ExitCode::OperationalError,
    };

    let mut stream = match client.connect().await {
        Ok(s) => s,
        Err(_) => return ExitCode::OperationalError,
    };

    let handshake_req = harness.create_handshake_request();
    if stream.send_envelope(handshake_req).await.is_err() {
        return ExitCode::OperationalError;
    }

    if let Ok(Some(resp)) = stream.recv_envelope().await {
        if harness.handle_handshake_response(&resp).await.is_err() {
            return ExitCode::OperationalError;
        }
    } else {
        return ExitCode::OperationalError;
    }

    ExitCode::Success
}
