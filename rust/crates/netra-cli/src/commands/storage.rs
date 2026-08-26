//! # `netra storage` Command Handlers (`netra-cli::commands::storage`)
//!
//! Subcommands for managing and inspecting the local SQLite storage subsystem:
//! - `status`: Database footprint, WAL size, and quota saturation.
//! - `check`: Tier 2 quick_check and Tier 3 deep integrity verification.
//! - `recover`: Safe quarantine recovery with explicit destructive confirmation.

use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::time::Instant;

use rusqlite::Connection;
use serde::Serialize;

use netra_core::config::NetraConfig;
use netra_core::storage::recovery::{IntegrityVerification, QuarantineManager, QuarantineMetadata};
use netra_core::storage::{
    ConfigRepository, DatabaseEngine, FindingsRepository, MigrationEngine,
    ObservationQueueRepository, StorageError,
};

use crate::cli::{CheckArgs, RecoverArgs, StorageSubcommand};
use crate::errors::{CliError, ExitCode};
use crate::output::formatting::format_box_block;
use crate::output::OutputPresenter;

/// Payload model for `netra storage status`.
#[derive(Debug, Clone, Serialize)]
pub struct StorageStatusData {
    pub db_path: PathBuf,
    pub total_size_bytes: u64,
    pub db_size_bytes: u64,
    pub wal_size_bytes: u64,
    pub shm_size_bytes: u64,
    pub max_storage_bytes: u64,
    pub saturation_percent: f64,
    pub records: StorageRecordCounts,
}

#[derive(Debug, Clone, Serialize)]
pub struct StorageRecordCounts {
    pub migrations_applied: usize,
    pub config_entries: usize,
    pub queued_observations: usize,
    pub total_findings: usize,
}

/// Payload model for `netra storage check`.
#[derive(Debug, Clone, Serialize)]
pub struct StorageCheckData {
    pub db_path: PathBuf,
    pub tier: u8,
    pub check_type: &'static str,
    pub duration_ms: u128,
    pub passed: bool,
    pub details: String,
}

/// Payload model for `netra storage recover`.
#[derive(Debug, Clone, Serialize)]
pub struct StorageRecoverData {
    pub db_path: PathBuf,
    pub quarantine_dir: PathBuf,
    pub metadata: QuarantineMetadata,
    pub reinitialized: bool,
}

/// Dispatches `netra storage` subcommands.
pub async fn execute(
    subcommand: &StorageSubcommand,
    config: &NetraConfig,
    storage: Option<&DatabaseEngine>,
    presenter: &OutputPresenter,
) -> Result<ExitCode, CliError> {
    match subcommand {
        StorageSubcommand::Status => execute_status(config, storage, presenter).await,
        StorageSubcommand::Check(args) => execute_check(args, config, storage, presenter).await,
        StorageSubcommand::Recover(args) => execute_recover(args, config, presenter).await,
    }
}

async fn execute_status(
    config: &NetraConfig,
    storage: Option<&DatabaseEngine>,
    presenter: &OutputPresenter,
) -> Result<ExitCode, CliError> {
    let db_path = config.storage.db_path.clone();
    let max_storage_bytes = config.storage.max_storage_bytes;

    let db_size_bytes = fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
    let wal_path = PathBuf::from(format!("{}-wal", db_path.display()));
    let wal_size_bytes = fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
    let shm_path = PathBuf::from(format!("{}-shm", db_path.display()));
    let shm_size_bytes = fs::metadata(&shm_path).map(|m| m.len()).unwrap_or(0);

    let total_size_bytes = db_size_bytes + wal_size_bytes + shm_size_bytes;
    let saturation_percent = if max_storage_bytes > 0 {
        (total_size_bytes as f64 / max_storage_bytes as f64) * 100.0
    } else {
        0.0
    };

    let counts = if let Some(eng) = storage {
        eng.with_reader(|conn| {
            let migrations: usize = conn
                .query_row("SELECT COUNT(*) FROM _netra_migrations", [], |row| {
                    row.get(0)
                })
                .unwrap_or(0);
            let config_entries = ConfigRepository::list(conn).map(|c| c.len()).unwrap_or(0);
            let queued_observations = ObservationQueueRepository::count_by_status(
                conn,
                netra_core::storage::ObservationStatus::Queued,
            )
            .unwrap_or(0) as usize;
            let total_findings =
                FindingsRepository::list_by_status(conn, netra_core::storage::FindingStatus::Open)
                    .map(|f| f.len())
                    .unwrap_or(0);

            Ok(StorageRecordCounts {
                migrations_applied: migrations,
                config_entries,
                queued_observations,
                total_findings,
            })
        })
        .await
        .unwrap_or(StorageRecordCounts {
            migrations_applied: 0,
            config_entries: 0,
            queued_observations: 0,
            total_findings: 0,
        })
    } else {
        StorageRecordCounts {
            migrations_applied: 0,
            config_entries: 0,
            queued_observations: 0,
            total_findings: 0,
        }
    };

    let data = StorageStatusData {
        db_path: db_path.clone(),
        total_size_bytes,
        db_size_bytes,
        wal_size_bytes,
        shm_size_bytes,
        max_storage_bytes,
        saturation_percent,
        records: counts.clone(),
    };

    let title = "NETRA Local Storage Status";
    presenter.emit_result("storage status", &data, |c| {
        let total_mb = total_size_bytes as f64 / (1024.0 * 1024.0);
        let max_mb = max_storage_bytes as f64 / (1024.0 * 1024.0);
        let wal_kb = wal_size_bytes as f64 / 1024.0;
        let shm_kb = shm_size_bytes as f64 / 1024.0;

        let sat_str = if saturation_percent >= 85.0 {
            c.red(&format!("{saturation_percent:.1}% (High Water Saturation)"))
        } else {
            c.green(&format!("{saturation_percent:.1}%"))
        };

        format_box_block(
            title,
            &[
                ("Database Path", db_path.display().to_string()),
                (
                    "Total Footprint",
                    format!("{total_mb:.2} MB (WAL: {wal_kb:.1} KB, SHM: {shm_kb:.1} KB)"),
                ),
                (
                    "Storage Quota",
                    format!("{max_mb:.0} MB (Saturation: {sat_str})"),
                ),
                (
                    "Migrations",
                    format!("{} applied", counts.migrations_applied),
                ),
                (
                    "Active Records",
                    format!(
                        "{} config entries, {} queued observations, {} open findings",
                        counts.config_entries, counts.queued_observations, counts.total_findings
                    ),
                ),
            ],
            c,
        )
    });

    Ok(ExitCode::Success)
}

async fn execute_check(
    args: &CheckArgs,
    config: &NetraConfig,
    _storage: Option<&DatabaseEngine>,
    presenter: &OutputPresenter,
) -> Result<ExitCode, CliError> {
    let db_path = config.storage.db_path.clone();

    if !db_path.exists() {
        let err = CliError::operational(
            "ERR_STORAGE_NOT_FOUND",
            format!("Database file does not exist at '{}'", db_path.display()),
        );
        presenter.emit_error("storage check", &err);
        return Ok(ExitCode::OperationalError);
    }

    let conn =
        match Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(c) => c,
            Err(e) => {
                let err = CliError::degraded(
                    "ERR_STORAGE_CORRUPTION",
                    format!("Failed to open database for verification: {e}"),
                );
                presenter.emit_error("storage check", &err);
                return Ok(ExitCode::DegradedState);
            }
        };

    let start = Instant::now();
    let (tier, check_type, passed, details) = if args.deep {
        match IntegrityVerification::probe_tier3_deep_check(&conn) {
            Ok(issues) => {
                if issues.is_empty() {
                    (
                        3,
                        "deep_integrity_check",
                        true,
                        "Tier 3 deep check passed cleanly".to_string(),
                    )
                } else {
                    (
                        3,
                        "deep_integrity_check",
                        false,
                        format!("Integrity issues detected: {}", issues.join("; ")),
                    )
                }
            }
            Err(StorageError::Corruption(reason)) => (
                3,
                "deep_integrity_check",
                false,
                format!("Corruption detected: {reason}"),
            ),
            Err(e) => (3, "deep_integrity_check", false, e.to_string()),
        }
    } else {
        match IntegrityVerification::probe_tier2_quick_check(&conn) {
            Ok(dur) => (
                2,
                "quick_check",
                true,
                format!(
                    "Tier 2 quick_check passed cleanly in {} ms",
                    dur.as_millis()
                ),
            ),
            Err(StorageError::Corruption(reason)) => (
                2,
                "quick_check",
                false,
                format!("Corruption detected: {reason}"),
            ),
            Err(e) => (2, "quick_check", false, e.to_string()),
        }
    };
    let duration_ms = start.elapsed().as_millis();

    let data = StorageCheckData {
        db_path: db_path.clone(),
        tier,
        check_type,
        duration_ms,
        passed,
        details: details.clone(),
    };

    let exit_code = if passed {
        ExitCode::Success
    } else {
        ExitCode::DegradedState
    };

    let title = format!("NETRA SQLite Integrity Verification (Tier {tier}: {check_type})");
    presenter.emit_result("storage check", &data, |c| {
        let status_colored = if passed {
            c.green("● PASSED")
        } else {
            c.red("✖ CORRUPTED")
        };

        format_box_block(
            &title,
            &[
                ("Database Path", db_path.display().to_string()),
                ("Verification Tier", format!("Tier {tier} ({check_type})")),
                ("Integrity Status", status_colored),
                ("Duration", format!("{duration_ms} ms")),
                ("Details", details),
            ],
            c,
        )
    });

    Ok(exit_code)
}

async fn execute_recover(
    args: &RecoverArgs,
    config: &NetraConfig,
    presenter: &OutputPresenter,
) -> Result<ExitCode, CliError> {
    let db_path = config.storage.db_path.clone();

    // 1. Check if database exists
    if !db_path.exists() {
        let err = CliError::operational(
            "ERR_STORAGE_NOT_FOUND",
            format!("No database found to recover at '{}'", db_path.display()),
        );
        presenter.emit_error("storage recover", &err);
        return Ok(ExitCode::OperationalError);
    }

    // 2. Destructive action confirmation safeguard
    let is_interactive = io::stdin().is_terminal();
    if !args.force_reinit {
        if is_interactive {
            let mut err_out = io::stderr().lock();
            let _ = writeln!(
                err_out,
                "\n{} WARNING: 'netra storage recover' will quarantine active database files and re-initialize a fresh store.",
                presenter.color_stderr.yellow("▲")
            );
            let _ = write!(
                err_out,
                "Do you want to proceed with quarantine and re-initialization? [y/N]: "
            );
            let _ = err_out.flush();

            let mut input = String::new();
            if io::stdin().read_line(&mut input).is_err()
                || (!input.trim().eq_ignore_ascii_case("y")
                    && !input.trim().eq_ignore_ascii_case("yes"))
            {
                let err = CliError::operational(
                    "ERR_RECOVERY_REFUSED",
                    "Storage recovery operation cancelled by operator.",
                );
                presenter.emit_error("storage recover", &err);
                return Ok(ExitCode::OperationalError);
            }
        } else {
            let err = CliError::operational(
                "ERR_RECOVERY_REFUSED",
                "Storage recovery refused in non-interactive environment without explicit '--force-reinit' flag.",
            );
            presenter.emit_error("storage recover", &err);
            return Ok(ExitCode::OperationalError);
        }
    }

    presenter.banner("Initiating database quarantine and safe re-initialization...");

    // 3. Execute safe quarantine via Phase 3 QuarantineManager
    let quarantine_dir = match QuarantineManager::execute_quarantine(
        &db_path,
        "Operator-initiated recovery via netra storage recover",
    ) {
        Ok(dir) => dir,
        Err(e) => {
            let err = CliError::operational(
                "ERR_QUARANTINE_FAILED",
                format!("Failed to quarantine database files: {e}"),
            );
            presenter.emit_error("storage recover", &err);
            return Ok(ExitCode::OperationalError);
        }
    };

    // 4. Read quarantine metadata
    let meta_file = quarantine_dir.join("quarantine_meta.json");
    let metadata: QuarantineMetadata = fs::read_to_string(&meta_file)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| QuarantineMetadata {
            quarantined_at: chrono::Utc::now().to_rfc3339(),
            original_db_path: db_path.display().to_string(),
            corruption_reason: "Manual operator recovery".to_string(),
            host_os: std::env::consts::OS.to_string(),
            files: Vec::new(),
        });

    // 5. Initialize fresh database and apply initial schema migrations
    let mut conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            let err = CliError::operational(
                "ERR_REINIT_FAILED",
                format!(
                    "Failed to create replacement database at '{}': {e}",
                    db_path.display()
                ),
            );
            presenter.emit_error("storage recover", &err);
            return Ok(ExitCode::OperationalError);
        }
    };

    if let Err(e) = DatabaseEngine::apply_pragmas(&conn) {
        let err = CliError::operational(
            "ERR_REINIT_FAILED",
            format!("Failed to apply SQLite pragmas to replacement database: {e}"),
        );
        presenter.emit_error("storage recover", &err);
        return Ok(ExitCode::OperationalError);
    }

    if let Err(e) = MigrationEngine::run_pending_migrations(&mut conn) {
        let err = CliError::operational(
            "ERR_REINIT_FAILED",
            format!("Failed to apply schema migrations to replacement database: {e}"),
        );
        presenter.emit_error("storage recover", &err);
        return Ok(ExitCode::OperationalError);
    }

    let data = StorageRecoverData {
        db_path: db_path.clone(),
        quarantine_dir: quarantine_dir.clone(),
        metadata,
        reinitialized: true,
    };

    let title = "NETRA Storage Recovery Complete";
    presenter.emit_result("storage recover", &data, |c| {
        format_box_block(
            title,
            &[
                ("Status", c.green("● SUCCESS")),
                ("Quarantine Directory", quarantine_dir.display().to_string()),
                (
                    "Replacement Database",
                    format!("Initialized at {}", db_path.display()),
                ),
                ("Migrations", "Schema v1 applied cleanly".to_string()),
            ],
            c,
        )
    });

    Ok(ExitCode::Success)
}
