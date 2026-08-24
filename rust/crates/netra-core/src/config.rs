use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{NetraError, Result};

/// Operational runtime modes for NETRA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeMode {
    /// On-demand command line invocation.
    Cli,
    /// Persistent background service managed by OS supervisor.
    Service,
}

impl Default for RuntimeMode {
    fn default() -> Self {
        Self::Cli
    }
}

/// Structured logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Log verbosity level: "trace", "debug", "info", "warn", "error".
    pub level: String,
    /// Output format: "human" (ANSI) or "json" (structured machine format).
    pub format: String,
    /// Whether ANSI colors should be suppressed.
    pub no_color: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "human".to_string(),
            no_color: false,
        }
    }
}

/// Control API and network transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Base URL for the central Control API Gateway.
    pub server_url: String,
    /// Heartbeat ping cadence in seconds.
    pub heartbeat_interval_seconds: u64,
    /// Hard network request timeout in seconds.
    pub timeout_seconds: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            server_url: "https://api.netra.io".to_string(),
            heartbeat_interval_seconds: 15,
            timeout_seconds: 30,
        }
    }
}

/// Local SQLite storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Path to local agent SQLite database file.
    pub db_path: PathBuf,
    /// Maximum storage quota in bytes (default: 500MB).
    pub max_storage_bytes: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("tmp/agent.db"),
            max_storage_bytes: 500 * 1024 * 1024, // 500 MB
        }
    }
}

/// Root configuration object for NETRA core runtime.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetraConfig {
    /// Active runtime mode.
    pub mode: RuntimeMode,
    /// Logging configuration.
    pub logging: LogConfig,
    /// Network & Control API settings.
    pub network: NetworkConfig,
    /// Local state storage settings.
    pub storage: StorageConfig,
}

impl NetraConfig {
    /// Creates a new default configuration instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads configuration from a TOML file on disk.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| NetraError::config(format!("Failed to read config file: {}", e)))?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| NetraError::config(format!("Invalid config TOML: {}", e)))?;
        config.validate()?;
        Ok(config)
    }

    /// Applies environment variable overrides to the active configuration.
    pub fn apply_env_overrides(&mut self) {
        if let Ok(level) = std::env::var("NETRA_LOG_LEVEL") {
            self.logging.level = level.to_lowercase();
        }
        if let Ok(format) = std::env::var("NETRA_LOG_FORMAT") {
            self.logging.format = format.to_lowercase();
        }
        if let Ok(url) = std::env::var("NETRA_SERVER_URL") {
            self.network.server_url = url;
        }
        if let Ok(db) = std::env::var("NETRA_LOCAL_DB_PATH") {
            self.storage.db_path = PathBuf::from(db);
        }
        if let Ok(no_color) = std::env::var("NO_COLOR") {
            self.logging.no_color = no_color == "1" || no_color.eq_ignore_ascii_case("true");
        }
    }

    /// Validates configuration parameters and boundaries.
    pub fn validate(&self) -> Result<()> {
        if self.network.heartbeat_interval_seconds == 0 {
            return Err(NetraError::config(
                "Heartbeat interval must be greater than 0",
            ));
        }
        if self.network.timeout_seconds == 0 {
            return Err(NetraError::config("Request timeout must be greater than 0"));
        }
        if self.storage.max_storage_bytes < 10 * 1024 * 1024 {
            return Err(NetraError::config(
                "Max storage quota cannot be less than 10MB",
            ));
        }
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.logging.level.as_str()) {
            return Err(NetraError::config(format!(
                "Invalid log level '{}', expected one of {:?}",
                self.logging.level, valid_levels
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validates() {
        let config = NetraConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.network.heartbeat_interval_seconds, 15);
    }

    #[test]
    fn test_invalid_heartbeat_fails_validation() {
        let mut config = NetraConfig::default();
        config.network.heartbeat_interval_seconds = 0;
        let err = config.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("Heartbeat interval must be greater than 0"));
    }

    #[test]
    fn test_toml_roundtrip() {
        let config = NetraConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        let deserialized: NetraConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.network.server_url, deserialized.network.server_url);
    }
}
