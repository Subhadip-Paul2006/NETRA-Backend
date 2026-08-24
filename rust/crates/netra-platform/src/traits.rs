use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use netra_core::error::Result;

/// Normalized operating system family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsFamily {
    Windows,
    Linux,
    MacOS,
    Unknown,
}

impl std::fmt::Display for OsFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsFamily::Windows => write!(f, "windows"),
            OsFamily::Linux => write!(f, "linux"),
            OsFamily::MacOS => write!(f, "macos"),
            OsFamily::Unknown => write!(f, "unknown"),
        }
    }
}

/// Host operating system metadata and environment snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformInfo {
    /// Operating system family (Windows, Linux, macOS).
    pub os_family: OsFamily,
    /// Detailed OS release / version string.
    pub os_version: String,
    /// Hardware architecture (x86_64, aarch64).
    pub arch: String,
    /// System hostname.
    pub hostname: String,
    /// Whether the process is currently executing with elevated root/SYSTEM privileges.
    pub is_elevated: bool,
}

/// Core OS platform adapter trait defining cross-platform behavioral contract.
#[async_trait]
pub trait PlatformAdapter: Send + Sync {
    /// Returns static platform details and capability envelope.
    async fn get_platform_info(&self) -> Result<PlatformInfo>;

    /// Checks if current execution context holds elevated privileges.
    fn is_elevated(&self) -> bool;

    /// Validates availability of platform-native security interfaces.
    async fn self_test(&self) -> Result<()>;
}
