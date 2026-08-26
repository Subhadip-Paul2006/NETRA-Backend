use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Configuration options for the NETRA Control-Plane REST API Gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Bind address (strictly limited to loopback addresses in Phase 5: 127.0.0.1 or ::1).
    pub host: String,
    /// Listening TCP port.
    pub port: u16,
    /// Request execution timeout in seconds.
    pub request_timeout_secs: u64,
    /// Maximum allowed request payload body in bytes (ceiling: 1MB).
    pub max_body_bytes: usize,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8443,
            request_timeout_secs: 15,
            max_body_bytes: 1024 * 1024, // 1MB ceiling
        }
    }
}

impl ApiConfig {
    /// Creates a default localhost-only API configuration.
    pub fn default_loopback() -> Self {
        Self::default()
    }

    /// Validates that the configured host address is strictly a local loopback IP.
    ///
    /// # Security Invariant
    /// In Phase 5, the REST API is unauthenticated under host-local trust assumptions.
    /// Binding to any non-loopback or public network interface is strictly prohibited.
    pub fn validate(&self) -> Result<(), String> {
        let ip = IpAddr::from_str(&self.host)
            .map_err(|e| format!("Invalid IP address format '{}': {}", self.host, e))?;

        if !ip.is_loopback() {
            return Err(format!(
                "Security violation: API host '{}' is not a loopback address. In Phase 5, only 127.0.0.1 and ::1 are permitted.",
                self.host
            ));
        }

        if self.max_body_bytes > 1024 * 1024 {
            return Err(format!(
                "Max body bytes ({}) exceeds the 1MB safety ceiling (1048576 bytes).",
                self.max_body_bytes
            ));
        }

        if self.request_timeout_secs == 0 || self.request_timeout_secs > 120 {
            return Err(format!(
                "Request timeout ({}s) must be between 1 and 120 seconds.",
                self.request_timeout_secs
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = ApiConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8443);
    }

    #[test]
    fn test_ipv6_loopback_is_valid() {
        let config = ApiConfig {
            host: "::1".to_string(),
            port: 8443,
            request_timeout_secs: 15,
            max_body_bytes: 1024 * 1024,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_public_ip_is_rejected() {
        let config = ApiConfig {
            host: "0.0.0.0".to_string(),
            port: 8443,
            request_timeout_secs: 15,
            max_body_bytes: 1024 * 1024,
        };
        assert!(config.validate().is_err());

        let lan_config = ApiConfig {
            host: "192.168.1.100".to_string(),
            port: 8443,
            request_timeout_secs: 15,
            max_body_bytes: 1024 * 1024,
        };
        assert!(lan_config.validate().is_err());
    }

    #[test]
    fn test_oversized_body_limit_is_rejected() {
        let config = ApiConfig {
            host: "127.0.0.1".to_string(),
            port: 8443,
            request_timeout_secs: 15,
            max_body_bytes: 2 * 1024 * 1024,
        };
        assert!(config.validate().is_err());
    }
}
