//! # Version Metadata (`netra-cli::version`)
//!
//! Exposes compile-time build, release, and output schema version metadata.

use serde::Serialize;

/// Canonical JSON output contract version (independent of application release version).
pub const SCHEMA_VERSION: &str = "1.0";

/// NETRA application release version derived from Cargo package metadata.
pub const NETRA_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Comprehensive version and build target metadata.
#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    /// Canonical JSON schema contract version.
    pub schema_version: &'static str,
    /// Application binary version.
    pub netra_version: &'static str,
    /// Target operating system family.
    pub target_os: &'static str,
    /// Target CPU architecture.
    pub target_arch: &'static str,
    /// Build profile ("debug" or "release").
    pub profile: &'static str,
    /// Open-source repository license.
    pub license: &'static str,
}

impl VersionInfo {
    /// Assembles compile-time version metadata for the current binary.
    pub fn current() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            netra_version: NETRA_VERSION,
            target_os: std::env::consts::OS,
            target_arch: std::env::consts::ARCH,
            profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            license: "Apache-2.0 / MIT",
        }
    }
}
