use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// NETRA — Network & Endpoint Threat Reconnaissance Architecture CLI
#[derive(Debug, Parser)]
#[command(
    name = "netra",
    author = "Subhadip Paul <subhadippaulff@gmail.com>",
    version = "1.0.0-foundation",
    about = "Open-Source Academic Defensive Security Reconnaissance & Engineering CLI",
    long_about = "NETRA provides deterministic, local-first endpoint posture audits, \
                  network reachability reasoning, and safe remediation verification."
)]
pub struct CliArgs {
    /// Emit machine-readable JSON output to stdout.
    #[arg(long, global = true)]
    pub json: bool,

    /// Suppress decorative banners and informational progress output.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Custom path to NETRA configuration TOML file.
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Pair this device with the NETRA Control Gateway using an enrollment token.
    Enroll(EnrollArgs),

    /// Display agent daemon status, connection state, and local health.
    Status,

    /// Trigger on-demand security posture audits.
    Scan(ScanArgs),

    /// Query and display detected security posture findings.
    Findings(FindingsArgs),

    /// Inspect local network neighbor ARP cache and routing reachability.
    Topology,

    /// Manage the background NETRA supervisor OS daemon service.
    Service(ServiceArgs),

    /// Generate an environmental and diagnostic debug bundle.
    Diagnostics,
}

#[derive(Debug, Args)]
pub struct EnrollArgs {
    /// One-time single-use device enrollment token.
    #[arg(value_name = "TOKEN")]
    pub token: String,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Run all standard posture audits (Network, Processes, Firewall, Users).
    #[arg(long)]
    pub all: bool,

    /// Audit active network sockets and listening ports.
    #[arg(long)]
    pub network: bool,

    /// Audit host packet filter and firewall rule profiles.
    #[arg(long)]
    pub firewall: bool,

    /// Audit active running process trees and binary hashes.
    #[arg(long)]
    pub processes: bool,

    /// Policy gate: exit with code 2 if findings equal or exceed severity.
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<String>,
}

#[derive(Debug, Args)]
pub struct FindingsArgs {
    #[command(subcommand)]
    pub action: Option<FindingsSubcommand>,
}

#[derive(Debug, Subcommand)]
pub enum FindingsSubcommand {
    /// List detected security posture findings.
    List {
        /// Filter by severity level (CRITICAL, HIGH, MEDIUM, LOW).
        #[arg(long)]
        severity: Option<String>,
    },
    /// Show detailed evidence artifact for a specific finding ID.
    Show {
        /// Finding identifier (e.g. fnd_01h8c4d5e6).
        id: String,
    },
}

#[derive(Debug, Args)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub action: ServiceSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ServiceSubcommand {
    /// Start the background supervisor daemon.
    Start,
    /// Stop the background supervisor daemon.
    Stop,
    /// Query the status of the background supervisor daemon.
    Status,
}
