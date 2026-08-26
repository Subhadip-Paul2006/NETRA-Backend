//! Handler for `netra findings` command.

use netra_core::config::NetraConfig;
use netra_core::storage::{DatabaseEngine, FindingSeverity, FindingStatus, FindingsRepository};

use crate::cli::{FindingsArgs, FindingsListArgs, FindingsSubcommand};
use crate::errors::{CliError, ExitCode};
use crate::output::formatting::format_box_block;
use crate::output::OutputPresenter;

/// Executes the findings command.
pub async fn execute_findings(
    args: &FindingsArgs,
    _config: &NetraConfig,
    storage: Option<&DatabaseEngine>,
    presenter: &OutputPresenter,
) -> Result<ExitCode, CliError> {
    let engine = storage.ok_or_else(|| {
        CliError::operational(
            "ERR_STORAGE_FAILURE",
            "Storage engine is required for findings operations",
        )
    })?;

    let action = args
        .action
        .as_ref()
        .unwrap_or(&FindingsSubcommand::List(FindingsListArgs {
            severity: None,
            status: None,
        }));

    match action {
        FindingsSubcommand::List(list_args) => {
            let status_filter = if let Some(ref st) = list_args.status {
                Some(st.parse::<FindingStatus>().map_err(|_| {
                    CliError::invalid_args(format!(
                        "Invalid finding status '{}'. Supported: OPEN, RESOLVED, SUPPRESSED",
                        st
                    ))
                })?)
            } else {
                None
            };

            let severity_filter = if let Some(ref sev) = list_args.severity {
                Some(sev.parse::<FindingSeverity>().map_err(|_| {
                    CliError::invalid_args(format!(
                        "Invalid finding severity '{}'. Supported: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL",
                        sev
                    ))
                })?)
            } else {
                None
            };

            // Query findings from repository
            let findings = engine
                .with_reader(move |conn| {
                    if let Some(status) = status_filter {
                        FindingsRepository::list_by_status(conn, status)
                    } else {
                        FindingsRepository::list_all(conn)
                    }
                })
                .await
                .map_err(|e| {
                    CliError::operational("ERR_DATABASE_ERROR", format!("Database error: {}", e))
                })?;

            // Apply in-memory severity filtering if specified
            let filtered_findings: Vec<_> = findings
                .into_iter()
                .filter(|f| {
                    if let Some(sev) = severity_filter {
                        f.severity == sev
                    } else {
                        true
                    }
                })
                .collect();

            let total_str = filtered_findings.len().to_string();

            presenter.emit_result("findings_list", &filtered_findings, |c| {
                let mut lines = Vec::new();
                lines.push(("Total Findings".to_string(), total_str.clone()));

                for (idx, f) in filtered_findings.iter().enumerate() {
                    let sev_str = f.severity.to_string();
                    let stat_str = f.status.to_string();
                    let occ_str = f.occurrence_count.to_string();

                    lines.push((
                        format!("[{}] {}", idx + 1, f.title),
                        format!("{} | {} | Occurrences: {}", sev_str, stat_str, occ_str),
                    ));
                }

                let str_refs: Vec<(&str, String)> =
                    lines.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();

                format_box_block("LOCAL SECURITY POSTURE FINDINGS", &str_refs, c)
            });

            Ok(ExitCode::Success)
        }
    }
}
