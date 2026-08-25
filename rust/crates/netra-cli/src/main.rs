//! # NETRA CLI (`netra-cli`)
//!
//! **Command-Line Interface & Diagnostic Tool for NETRA**
//!
//! `netra-cli` provides the user-facing CLI binary (`netra`) implementing the Unix
//! philosophy of separation of concerns:
//!
//! - **Standard Output (`stdout`)**: Exclusively reserved for machine-readable JSON data.
//! - **Standard Error (`stderr`)**: Reserved for human diagnostic output, ANSI formatting, and progress banners.
//! - **Standard Exit Codes**: `0` (Success), `1` (Operational Error), `2` (Policy Violation), `3` (Fatal Error).
//!
//! ## Architectural Invariants & Crate Boundaries
//!
//! 1. **Dependency Direction**: `netra-cli` consumes public APIs from `netra-core` and `netra-platform`.
//!    Neither `netra-core` nor `netra-platform` depends on `netra-cli`.
//! 2. **Interface Separation**: `netra-cli` contains no OS-specific security logic, no SQLite persistence
//!    logic, and no remediation execution code.

use std::process::ExitCode as StdExitCode;

use clap::Parser;
use serde_json::json;

mod args;
mod exit_codes;
mod output;

use args::{CliArgs, Commands};
use exit_codes::ExitCode;
use netra_core::config::NetraConfig;
use netra_core::logging::init_logging;
use netra_core::runtime::RuntimeCoordinator;
use netra_platform::{create_platform_adapter, detect_platform_info};
use output::OutputPresenter;

#[tokio::main]
async fn main() -> StdExitCode {
    let args = CliArgs::parse();
    let presenter = OutputPresenter::new(args.json, args.quiet);

    // 1. Initialize configuration
    let mut config = if let Some(path) = &args.config {
        match NetraConfig::from_file(path) {
            Ok(cfg) => cfg,
            Err(err) => {
                presenter.emit_error("config", &err);
                return ExitCode::OperationalError.into();
            }
        }
    } else {
        NetraConfig::default()
    };

    config.apply_env_overrides();

    // 2. Initialize structured logging
    if let Err(err) = init_logging(&config.logging) {
        presenter.emit_error("logging", &err);
        return ExitCode::OperationalError.into();
    }

    // 3. Initialize RuntimeCoordinator and platform adapter
    let coordinator = RuntimeCoordinator::new();
    let platform_adapter = create_platform_adapter();

    if let Err(err) = coordinator.register_component(platform_adapter).await {
        presenter.emit_error("runtime_registration", &err);
        return ExitCode::OperationalError.into();
    }

    if let Err(err) = coordinator.initialize().await {
        presenter.emit_error("runtime_init", &err);
        return ExitCode::OperationalError.into();
    }

    if let Err(err) = coordinator.start().await {
        presenter.emit_error("runtime_start", &err);
        return ExitCode::OperationalError.into();
    }

    // 4. Dispatch command
    let code = match execute_command(&args, &config, &coordinator, &presenter).await {
        Ok(code) => code,
        Err(err) => {
            presenter.emit_error("execution", &err);
            ExitCode::OperationalError
        }
    };

    // 5. Graceful shutdown of runtime
    let _ = coordinator.shutdown().await;

    code.into()
}

async fn execute_command(
    args: &CliArgs,
    _config: &NetraConfig,
    coordinator: &RuntimeCoordinator,
    presenter: &OutputPresenter,
) -> Result<ExitCode, netra_core::error::NetraError> {
    match &args.command {
        None | Some(Commands::Status) => {
            let platform = detect_platform_info();
            let state = coordinator.state().await;
            let health = coordinator.health().await;
            let summary = format!(
                "NETRA Host Security Agent (v1.0.0-foundation)\n\
                ─────────────────────────────────────────────────────────────\n\
                  OS Family:       {}\n\
                  Architecture:    {}\n\
                  Hostname:        {}\n\
                  Runtime State:   ● {}\n\
                  Health Status:   ● {}\n\
                ─────────────────────────────────────────────────────────────",
                platform.os_family, platform.arch, platform.hostname, state, health
            );

            presenter.emit_success(
                "status",
                json!({
                    "version": "1.0.0-foundation",
                    "status": state.to_string(),
                    "health": health.to_string(),
                    "platform": platform,
                }),
                &summary,
            );
            Ok(ExitCode::Success)
        }

        Some(Commands::Diagnostics) => {
            let platform = detect_platform_info();
            let state = coordinator.state().await;
            let health = coordinator.health().await;
            let priv_str = if platform.is_elevated {
                "ELEVATED"
            } else {
                "STANDARD_USER"
            };
            let summary = format!(
                "NETRA Environment Diagnostics Bundle\n\
                ─────────────────────────────────────────────────────────────\n\
                  Platform:        {} ({})\n\
                  Arch:            {}\n\
                  Hostname:        {}\n\
                  Privilege:       {}\n\
                  Runtime State:   {}\n\
                  Runtime Health:  {}\n\
                  Foundation:      Ready for Phase 02 Execution\n\
                ─────────────────────────────────────────────────────────────",
                platform.os_family,
                platform.os_version,
                platform.arch,
                platform.hostname,
                priv_str,
                state,
                health
            );

            presenter.emit_success(
                "diagnostics",
                json!({
                    "diagnostics": {
                        "platform": platform,
                        "runtime_state": "HEALTHY",
                        "phase": "01_FOUNDATION",
                    }
                }),
                &summary,
            );
            Ok(ExitCode::Success)
        }

        Some(Commands::Enroll(enroll_args)) => {
            presenter.banner("Initiating device enrollment with token: [REDACTED]");
            presenter.emit_success(
                "enroll",
                json!({
                    "action": "enroll",
                    "token_received": !enroll_args.token.is_empty(),
                    "status": "SKELETON_READY",
                    "message": "Device enrollment protocol scheduled for Phase 06 implementation",
                }),
                "✔ Device enrollment CLI interface verified (Phase 01 Foundation).",
            );
            Ok(ExitCode::Success)
        }

        Some(Commands::Scan(scan_args)) => {
            presenter.emit_success(
                "scan",
                json!({
                    "action": "scan",
                    "all": scan_args.all,
                    "network": scan_args.network,
                    "firewall": scan_args.firewall,
                    "processes": scan_args.processes,
                    "fail_on": scan_args.fail_on,
                    "status": "SKELETON_READY",
                    "message": "Scanner capabilities scheduled for Phase 07 implementation",
                }),
                "✔ Security scanner CLI interface verified (Phase 01 Foundation).",
            );
            Ok(ExitCode::Success)
        }

        Some(Commands::Findings(findings_args)) => {
            let action_desc = match &findings_args.action {
                Some(args::FindingsSubcommand::List { severity }) => {
                    format!("list (severity: {:?})", severity)
                }
                Some(args::FindingsSubcommand::Show { id }) => {
                    format!("show finding {}", id)
                }
                None => "list (all)".to_string(),
            };
            presenter.emit_success(
                "findings",
                json!({
                    "action": "findings",
                    "query": action_desc,
                    "total": 0,
                    "findings": [],
                    "status": "SKELETON_READY",
                    "message": "Finding reasoning engine scheduled for Phase 11 implementation",
                }),
                "✔ Findings query CLI interface verified (Phase 01 Foundation).",
            );
            Ok(ExitCode::Success)
        }

        Some(Commands::Topology) => {
            presenter.emit_success(
                "topology",
                json!({
                    "action": "topology",
                    "nodes": [],
                    "links": [],
                    "status": "SKELETON_READY",
                    "message": "Topology engine scheduled for Phase 08 implementation",
                }),
                "✔ Topology reachability CLI interface verified (Phase 01 Foundation).",
            );
            Ok(ExitCode::Success)
        }

        Some(Commands::Service(svc_args)) => {
            let action_name = match &svc_args.action {
                args::ServiceSubcommand::Start => "start",
                args::ServiceSubcommand::Stop => "stop",
                args::ServiceSubcommand::Status => "status",
            };
            let summary = format!(
                "✔ Service command '{}' CLI interface verified (Phase 01 Foundation).",
                action_name
            );
            presenter.emit_success(
                "service",
                json!({
                    "action": action_name,
                    "status": "SKELETON_READY",
                    "message": "Supervisor service scheduled for Phase 02 implementation",
                }),
                &summary,
            );
            Ok(ExitCode::Success)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_codes() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::OperationalError.as_i32(), 1);
        assert_eq!(ExitCode::PolicyFailure.as_i32(), 2);
        assert_eq!(ExitCode::InvalidArguments.as_i32(), 3);
    }

    #[test]
    fn test_cli_parsing_status() {
        let args = CliArgs::try_parse_from(["netra", "status"]).unwrap();
        assert!(matches!(args.command, Some(Commands::Status)));
        assert!(!args.json);
    }

    #[test]
    fn test_cli_parsing_json_flag() {
        let args = CliArgs::try_parse_from(["netra", "--json", "diagnostics"]).unwrap();
        assert!(matches!(args.command, Some(Commands::Diagnostics)));
        assert!(args.json);
    }

    #[test]
    fn test_cli_parsing_scan_flags() {
        let args =
            CliArgs::try_parse_from(["netra", "scan", "--all", "--fail-on", "HIGH"]).unwrap();
        if let Some(Commands::Scan(scan_args)) = args.command {
            assert!(scan_args.all);
            assert_eq!(scan_args.fail_on.as_deref(), Some("HIGH"));
        } else {
            panic!("Expected scan command");
        }
    }

    #[test]
    fn test_cli_parsing_findings() {
        let args = CliArgs::try_parse_from(["netra", "findings", "show", "fnd_01h8c4"]).unwrap();
        if let Some(Commands::Findings(f_args)) = args.command {
            assert!(matches!(
                f_args.action,
                Some(args::FindingsSubcommand::Show { ref id }) if id == "fnd_01h8c4"
            ));
        } else {
            panic!("Expected findings command");
        }
    }
}
