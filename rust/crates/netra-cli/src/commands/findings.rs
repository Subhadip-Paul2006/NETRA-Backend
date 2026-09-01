//! Handler for `netra findings` command hierarchy.

use netra_core::config::NetraConfig;
use netra_core::rules::RuleEngine;
use netra_core::storage::{
    DatabaseEngine, FindingSeverity, FindingStatus, FindingsCountFilter, FindingsRepository,
};

use crate::cli::{
    FindingsArgs, FindingsCountArgs, FindingsListArgs, FindingsShowArgs, FindingsSubcommand,
};
use crate::errors::{CliError, ExitCode};
use crate::output::formatting::format_box_block;
use crate::output::OutputPresenter;

/// Executes the findings command hierarchy.
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

    let default_list = FindingsSubcommand::List(FindingsListArgs::default());
    let action = args.action.as_ref().unwrap_or(&default_list);

    match action {
        FindingsSubcommand::List(list_args) => execute_list(list_args, engine, presenter).await,
        FindingsSubcommand::Show(show_args) => execute_show(show_args, engine, presenter).await,
        FindingsSubcommand::Count(count_args) => execute_count(count_args, engine, presenter).await,
    }
}

/// Executes `netra findings list`.
async fn execute_list(
    list_args: &FindingsListArgs,
    engine: &DatabaseEngine,
    presenter: &OutputPresenter,
) -> Result<ExitCode, CliError> {
    let status_filter = parse_status(list_args.status.as_deref())?;
    let severity_filter = parse_severity(list_args.severity.as_deref())?;
    let rule_filter = validate_and_resolve_rule(list_args.rule.as_deref())?;

    if let Some(limit) = list_args.limit {
        if limit == 0 {
            return Err(CliError::invalid_args("Limit must be greater than 0"));
        }
    }

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

    // Apply severity and rule filters
    let mut filtered_findings: Vec<_> = findings
        .into_iter()
        .filter(|f| {
            if let Some(sev) = severity_filter {
                if f.severity != sev {
                    return false;
                }
            }
            if let Some(ref r_id) = rule_filter {
                if &f.rule_id != r_id {
                    return false;
                }
            }
            true
        })
        .collect();

    // Apply limit truncation if specified
    if let Some(limit) = list_args.limit {
        filtered_findings.truncate(limit);
    }

    let total_str = filtered_findings.len().to_string();

    presenter.emit_result("findings_list", &filtered_findings, |c| {
        if filtered_findings.is_empty() {
            return format_box_block(
                "LOCAL SECURITY POSTURE FINDINGS (Total: 0)",
                &[("Findings", "No recorded findings matching filter criteria".to_string())],
                c,
            );
        }

        let title = format!("LOCAL SECURITY POSTURE FINDINGS (Total: {})", total_str);
        let mut rows = Vec::new();

        for (idx, f) in filtered_findings.iter().enumerate() {
            let fp_short = if f.fingerprint.len() >= 12 {
                &f.fingerprint[..12]
            } else {
                &f.fingerprint
            };

            let parsed: serde_json::Value = serde_json::from_str(&f.evidence_summary_json)
                .unwrap_or_else(|_| serde_json::json!({}));
            let target_key = parsed["target_key"].as_str().unwrap_or("-");

            let header = format!("[{}] {}...  {}", idx + 1, fp_short, f.rule_id);
            let details = format!(
                "Title: {}\n  Severity: {:<10} Status: {:<10} Occurrences: {}\n  Target: {}\n  Last Seen: {} (First Seen: {})",
                f.title,
                f.severity,
                f.status,
                f.occurrence_count,
                target_key,
                f.last_seen,
                f.first_seen
            );

            rows.push((header, details));
        }

        let str_refs: Vec<(&str, String)> =
            rows.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();

        format_box_block(&title, &str_refs, c)
    });

    Ok(ExitCode::Success)
}

/// Executes `netra findings show <FINGERPRINT>`.
async fn execute_show(
    show_args: &FindingsShowArgs,
    engine: &DatabaseEngine,
    presenter: &OutputPresenter,
) -> Result<ExitCode, CliError> {
    let validated_fp = validate_fingerprint(&show_args.fingerprint)?;
    let fp_owned = validated_fp.to_string();

    let finding_opt = engine
        .with_reader(move |conn| FindingsRepository::get(conn, &fp_owned))
        .await
        .map_err(|e| {
            CliError::operational("ERR_DATABASE_ERROR", format!("Database error: {}", e))
        })?;

    let finding = match finding_opt {
        Some(f) => f,
        None => {
            return Err(CliError::new(
                "ERR_NOT_FOUND",
                format!(
                    "Finding with fingerprint '{}' not found",
                    show_args.fingerprint.trim()
                ),
                ExitCode::InvalidArguments,
            ));
        }
    };

    presenter.emit_result("findings_show", &finding, |c| {
        let parsed: serde_json::Value = serde_json::from_str(&finding.evidence_summary_json)
            .unwrap_or_else(|_| serde_json::json!({}));

        let mut rows: Vec<(&str, String)> = vec![
            ("Fingerprint", finding.fingerprint.clone()),
            ("Rule ID", finding.rule_id.clone()),
            ("Severity", finding.severity.to_string()),
            ("Status", finding.status.to_string()),
            ("Occurrences", finding.occurrence_count.to_string()),
            ("First Seen", finding.first_seen.clone()),
            ("Last Seen", finding.last_seen.clone()),
            ("Title", finding.title.clone()),
        ];

        if let Some(target_key) = parsed["target_key"].as_str() {
            rows.push(("Target Key", target_key.to_string()));
        }

        if let Some(reason) = parsed["reason"].as_str() {
            rows.push(("Reason", reason.to_string()));
        }

        if let Some(remediation) = parsed["remediation"].as_str() {
            rows.push(("Remediation Guidance", remediation.to_string()));
        }

        format_box_block("FINDING DETAILS", &rows, c)
    });

    Ok(ExitCode::Success)
}

/// Executes `netra findings count`.
async fn execute_count(
    count_args: &FindingsCountArgs,
    engine: &DatabaseEngine,
    presenter: &OutputPresenter,
) -> Result<ExitCode, CliError> {
    let status_filter = parse_status(count_args.status.as_deref())?;
    let severity_filter = parse_severity(count_args.severity.as_deref())?;
    let rule_filter = validate_and_resolve_rule(count_args.rule.as_deref())?;

    let filter = FindingsCountFilter {
        status: status_filter,
        severity: severity_filter,
        rule_id: rule_filter,
    };

    let stats = engine
        .with_reader(move |conn| FindingsRepository::count_summary(conn, &filter))
        .await
        .map_err(|e| {
            CliError::operational("ERR_DATABASE_ERROR", format!("Database error: {}", e))
        })?;

    presenter.emit_result("findings_count", &stats, |c| {
        let rows = vec![
            ("Total Findings", stats.total.to_string()),
            ("Status: OPEN", stats.by_status.open.to_string()),
            ("Status: RESOLVED", stats.by_status.resolved.to_string()),
            ("Status: SUPPRESSED", stats.by_status.suppressed.to_string()),
            ("Severity: CRITICAL", stats.by_severity.critical.to_string()),
            ("Severity: HIGH", stats.by_severity.high.to_string()),
            ("Severity: MEDIUM", stats.by_severity.medium.to_string()),
            ("Severity: LOW", stats.by_severity.low.to_string()),
            (
                "Severity: INFORMATIONAL",
                stats.by_severity.informational.to_string(),
            ),
        ];

        format_box_block("FINDINGS SUMMARY", &rows, c)
    });

    Ok(ExitCode::Success)
}

/// Validates that a string is a 64-character hexadecimal SHA-256 fingerprint.
fn validate_fingerprint(fp: &str) -> Result<&str, CliError> {
    let trimmed = fp.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(trimmed)
    } else {
        Err(CliError::invalid_args(
            "Invalid fingerprint format: must be a 64-character hexadecimal SHA-256 string",
        ))
    }
}

/// Validates and deterministically resolves a rule filter string.
fn validate_and_resolve_rule(rule_str: Option<&str>) -> Result<Option<String>, CliError> {
    if let Some(raw) = rule_str {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CliError::invalid_args(
                "Invalid rule filter: rule ID cannot be empty",
            ));
        }
        match RuleEngine::resolve_rule_id(trimmed) {
            Some(resolved) => Ok(Some(resolved)),
            None => Err(CliError::invalid_args(format!(
                "Invalid rule identifier '{}'. Must be an exact registered rule ID (e.g. NET-003-GATEWAY-OFF-SUBNET) or canonical short ID (e.g. NET-003)",
                trimmed
            ))),
        }
    } else {
        Ok(None)
    }
}

/// Parses an optional finding status string.
fn parse_status(st: Option<&str>) -> Result<Option<FindingStatus>, CliError> {
    if let Some(raw) = st {
        let trimmed = raw.trim();
        trimmed.parse::<FindingStatus>().map(Some).map_err(|_| {
            CliError::invalid_args(format!(
                "Invalid finding status '{}'. Supported: OPEN, RESOLVED, SUPPRESSED",
                trimmed
            ))
        })
    } else {
        Ok(None)
    }
}

/// Parses an optional finding severity string.
fn parse_severity(sev: Option<&str>) -> Result<Option<FindingSeverity>, CliError> {
    if let Some(raw) = sev {
        let trimmed = raw.trim();
        trimmed.parse::<FindingSeverity>().map(Some).map_err(|_| {
            CliError::invalid_args(format!(
                "Invalid finding severity '{}'. Supported: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL",
                trimmed
            ))
        })
    } else {
        Ok(None)
    }
}
