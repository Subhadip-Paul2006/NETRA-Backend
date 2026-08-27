//! Handler for `netra scan` command.

use std::sync::Arc;

use netra_core::config::NetraConfig;
use netra_core::id::DeviceId;
use netra_core::observation::{ObservationType, ScannerSupervisor};
use netra_core::storage::repositories::identity::DeviceIdentityRepository;
use netra_core::storage::{DatabaseEngine, FindingSeverity, FindingStatus, FindingsRepository};
use netra_platform::scanners::create_all_platform_scanners;

use crate::cli::ScanArgs;
use crate::errors::{CliError, ExitCode};
use crate::output::formatting::format_box_block;
use crate::output::OutputPresenter;

/// Executes the posture scan command across all or specific observation domains.
pub async fn execute_scan(
    args: &ScanArgs,
    _config: &NetraConfig,
    storage: Option<&DatabaseEngine>,
    presenter: &OutputPresenter,
) -> Result<ExitCode, CliError> {
    let engine = storage.ok_or_else(|| {
        CliError::operational(
            "ERR_STORAGE_FAILURE",
            "Storage engine is required for scanning operations",
        )
    })?;

    // Query device identity provenance (or generate fallback if unenrolled)
    let identity = engine
        .with_reader(DeviceIdentityRepository::get)
        .await
        .map_err(|e| {
            CliError::operational("ERR_DATABASE_ERROR", format!("Database error: {}", e))
        })?;

    let device_id = match identity {
        Some(id_rec) => match DeviceId::parse_str(&id_rec.device_id) {
            Ok(d) => d,
            Err(_) => DeviceId::new(),
        },
        None => DeviceId::new(),
    };

    let scanners = create_all_platform_scanners(args.hash_binaries);
    let supervisor = ScannerSupervisor::new(Arc::new(engine.clone()), scanners);

    let scan_result = if let Some(ref domain_str) = args.domain {
        let domain = parse_domain_string(domain_str).ok_or_else(|| {
            CliError::invalid_args(format!(
                "Invalid scanner domain '{}'. Supported: sockets, process, firewall, users, services, os",
                domain_str
            ))
        })?;
        supervisor.run_single_domain_scan(domain, &device_id).await
    } else {
        supervisor.run_scan_cycle(&device_id).await
    };

    let res = scan_result.map_err(|e| {
        CliError::operational("ERR_SCAN_FAILURE", format!("Scan cycle failed: {}", e))
    })?;

    // Query open findings with critical/high severity to determine exit code
    let open_findings = engine
        .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
        .await
        .map_err(|e| {
            CliError::operational("ERR_DATABASE_ERROR", format!("Database error: {}", e))
        })?;

    let has_critical_or_high = open_findings
        .iter()
        .any(|f| f.severity == FindingSeverity::Critical || f.severity == FindingSeverity::High);

    let dur_str = format!("{} ms", res.duration_ms);
    let total_sc_str = res.total_scanners.to_string();
    let succ_sc_str = res.successful_scanners.to_string();
    let obs_str = res.observations_collected.to_string();
    let f_eval_str = res.findings_evaluated.to_string();
    let act_f_str = res.active_open_findings.to_string();

    presenter.emit_result("scan_result", &res, |c| {
        format_box_block(
            "SECURITY POSTURE SCAN RESULTS",
            &[
                ("Total Scanners", total_sc_str),
                ("Successful Collectors", succ_sc_str),
                ("Observations Enqueued", obs_str),
                ("Findings Evaluated", f_eval_str),
                ("Active Open Findings", act_f_str),
                ("Scan Duration", dur_str),
            ],
            c,
        )
    });

    if has_critical_or_high {
        Ok(ExitCode::PolicyFailure) // Exit code 2 for detected CRITICAL or HIGH findings
    } else {
        Ok(ExitCode::Success)
    }
}

fn parse_domain_string(s: &str) -> Option<ObservationType> {
    match s.to_lowercase().as_str() {
        "socket" | "sockets" => Some(ObservationType::Sockets),
        "proc" | "process" | "processes" => Some(ObservationType::Processes),
        "fw" | "firewall" => Some(ObservationType::Firewall),
        "user" | "users" | "account" | "accounts" => Some(ObservationType::Users),
        "svc" | "service" | "services" => Some(ObservationType::Services),
        "os" | "os_config" | "config" => Some(ObservationType::OsConfig),
        "interface" | "interfaces" | "iface" | "ifaces" | "net" | "network" => {
            Some(ObservationType::Interfaces)
        }
        "route" | "routes" | "routing" => Some(ObservationType::Routes),
        "dns" => Some(ObservationType::Dns),
        "neighbor" | "neighbors" | "arp" => Some(ObservationType::Neighbors),
        _ => None,
    }
}
