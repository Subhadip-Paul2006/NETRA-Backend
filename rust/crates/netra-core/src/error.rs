use std::fmt;

use thiserror::Error;

/// Standard Result type alias for NETRA operations.
pub type Result<T> = std::result::Result<T, NetraError>;

/// Categorized error taxonomy for NETRA subsystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ErrorKind {
    #[error("Configuration Error")]
    Config,

    #[error("Identifier Error")]
    Identifier,

    #[error("Platform / OS Adapter Error")]
    Platform,

    #[error("Authentication & Attestation Error")]
    Auth,

    #[error("Storage & Database Error")]
    Storage,

    #[error("Network & Transport Error")]
    Network,

    #[error("Policy & Capability Whitelist Error")]
    Policy,

    #[error("Input / Output Error")]
    Io,

    #[error("Internal System Error")]
    Internal,
}

impl ErrorKind {
    /// Returns the stable alphanumeric machine code.
    pub fn code(&self) -> &'static str {
        match self {
            ErrorKind::Config => "ERR_CONFIG_INVALID",
            ErrorKind::Identifier => "ERR_IDENTIFIER_INVALID",
            ErrorKind::Platform => "ERR_PLATFORM_ERROR",
            ErrorKind::Auth => "ERR_AUTH_REJECTED",
            ErrorKind::Storage => "ERR_STORAGE_FAILURE",
            ErrorKind::Network => "ERR_NETWORK_UNREACHABLE",
            ErrorKind::Policy => "ERR_POLICY_VIOLATION",
            ErrorKind::Io => "ERR_IO_ERROR",
            ErrorKind::Internal => "ERR_INTERNAL_ERROR",
        }
    }
}

/// Unified error structure maintaining machine code, human message, and optional safe context.
#[derive(Debug, Clone, Error)]
pub struct NetraError {
    kind: ErrorKind,
    message: String,
    safe_context: Option<String>,
}

impl NetraError {
    /// Creates a new error with kind and message.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            safe_context: None,
        }
    }

    /// Appends safe, non-sensitive context for debugging.
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.safe_context = Some(context.into());
        self
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn code(&self) -> &'static str {
        self.kind.code()
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn safe_context(&self) -> Option<&str> {
        self.safe_context.as_deref()
    }

    // Helper constructors
    pub fn config(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Config, msg)
    }

    pub fn invalid_identifier(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Identifier, msg)
    }

    pub fn platform(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Platform, msg)
    }

    pub fn auth(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Auth, msg)
    }

    pub fn storage(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Storage, msg)
    }

    pub fn network(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Network, msg)
    }

    pub fn policy(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Policy, msg)
    }

    pub fn io(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Io, msg)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, msg)
    }
}

impl fmt::Display for NetraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.kind.code(), self.message)?;
        if let Some(ctx) = &self.safe_context {
            write!(f, " (Context: {})", ctx)?;
        }
        Ok(())
    }
}

impl From<std::io::Error> for NetraError {
    fn from(err: std::io::Error) -> Self {
        Self::new(ErrorKind::Io, err.to_string())
    }
}

impl From<serde_json::Error> for NetraError {
    fn from(err: serde_json::Error) -> Self {
        Self::new(ErrorKind::Config, format!("JSON serialization error: {}", err))
    }
}

impl From<toml::de::Error> for NetraError {
    fn from(err: toml::de::Error) -> Self {
        Self::new(ErrorKind::Config, format!("TOML parse error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation_and_display() {
        let err = NetraError::config("Missing required field").with_context("field=server_url");
        assert_eq!(err.kind(), ErrorKind::Config);
        assert_eq!(err.code(), "ERR_CONFIG_INVALID");
        assert!(err.to_string().contains("[ERR_CONFIG_INVALID] Missing required field"));
        assert!(err.to_string().contains("field=server_url"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let netra_err: NetraError = io_err.into();
        assert_eq!(netra_err.kind(), ErrorKind::Io);
        assert_eq!(netra_err.code(), "ERR_IO_ERROR");
    }
}
