//! # CLI Argument & Command Hierarchy (`netra-cli::cli`)
//!
//! Strongly-typed Clap v4 command taxonomy with global formatting flags.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// NETRA — Network & Endpoint Threat Reconnaissance Architecture CLI
#[derive(Debug, Parser)]
#[command(
    name = "netra",
    author = "Subhadip Paul <subhadippaulff@gmail.com>",
    version = env!("CARGO_PKG_VERSION"),
    about = "Open-Source Academic Defensive Security Reconnaissance & Engineering CLI",
    long_about = "NETRA provides deterministic, local-first endpoint posture audits, \
                  network reachability reasoning, and safe remediation verification."
)]
pub struct CliArgs {
    /// Emit machine-readable JSON output to stdout.
    #[arg(long, global = true)]
    pub json: bool,

    /// Suppress informational headers, banners, and progress indicators on stderr.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Disable ANSI color escape sequences in terminal output.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Custom path to NETRA configuration TOML file.
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Hidden launcher flag indicating execution as Tier-2 low-privilege worker.
    #[arg(long, hide = true)]
    pub worker: bool,

    /// Hidden ephemeral IPC token passed from supervisor to worker.
    #[arg(long, hide = true, value_name = "TOKEN")]
    pub ipc_token: Option<String>,

    /// Subcommand to execute. If omitted, defaults to `status`.
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Display agent runtime status, platform attributes, and storage health.
    Status,

    /// Generate comprehensive local debug and environment diagnostic bundle.
    Diagnostics,

    /// Inspect and manage embedded SQLite database and storage engine.
    Storage(StorageArgs),

    /// Display detailed build, commit, and platform target metadata.
    Version,
}

#[derive(Debug, Args)]
pub struct StorageArgs {
    #[command(subcommand)]
    pub action: StorageSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum StorageSubcommand {
    /// Display database disk footprint, WAL size, and quota saturation.
    Status,

    /// Run tiered integrity checks on the local SQLite database.
    Check(CheckArgs),

    /// Quarantine active database and safely re-initialize fresh store.
    Recover(RecoverArgs),
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Execute Tier 3 deep verification (PRAGMA integrity_check + foreign_key_check) instead of Tier 2 quick_check.
    #[arg(long)]
    pub deep: bool,
}

#[derive(Debug, Args)]
pub struct RecoverArgs {
    /// Force recovery without interactive confirmation in non-interactive/CI environments.
    #[arg(long)]
    pub force_reinit: bool,
}
