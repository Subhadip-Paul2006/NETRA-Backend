//! # CLI Error Taxonomy & Exit Codes (`netra-cli::errors`)
//!
//! Maps internal domain errors to standardized POSIX exit codes and user-safe error payloads.

use std::fmt;
use std::process::ExitCode as StdExitCode;

use netra_core::error::{ErrorKind, NetraError};
use netra_core::storage::StorageError;

/// Standard exit codes for NETRA CLI executions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    /// Command completed successfully without error.
    Success = 0,
    /// Generic operational or runtime error (I/O, network unreachable, permission failure).
    OperationalError = 1,
    /// Security audit failed policy threshold (`--fail-on`).
    PolicyFailure = 2,
    /// Invalid arguments or malformed CLI syntax.
    InvalidArguments = 3,
    /// System is running in a degraded or quarantined state.
    DegradedState = 4,
}

impl ExitCode {
    pub fn as_i32(&self) -> i32 {
        *self as i32
    }
}

impl From<ExitCode> for StdExitCode {
    fn from(code: ExitCode) -> Self {
        StdExitCode::from(code as u8)
    }
}

/// Structured CLI error containing user-facing code, message, and exit status.
#[derive(Debug)]
pub struct CliError {
    pub code: String,
    pub message: String,
    pub exit_code: ExitCode,
    pub context: Option<serde_json::Value>,
}

impl CliError {
    pub fn new(code: impl Into<String>, message: impl Into<String>, exit_code: ExitCode) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            exit_code,
            context: None,
        }
    }

    pub fn with_context(mut self, context: serde_json::Value) -> Self {
        self.context = Some(context);
        self
    }

    pub fn invalid_args(message: impl Into<String>) -> Self {
        Self::new("ERR_INVALID_ARGUMENTS", message, ExitCode::InvalidArguments)
    }

    pub fn operational(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(code, message, ExitCode::OperationalError)
    }

    pub fn degraded(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(code, message, ExitCode::DegradedState)
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for CliError {}

impl From<NetraError> for CliError {
    fn from(err: NetraError) -> Self {
        let exit_code = match err.kind() {
            ErrorKind::Config | ErrorKind::Identifier => ExitCode::InvalidArguments,
            ErrorKind::Policy => ExitCode::PolicyFailure,
            ErrorKind::Storage
            | ErrorKind::Platform
            | ErrorKind::Auth
            | ErrorKind::Network
            | ErrorKind::Runtime
            | ErrorKind::Io
            | ErrorKind::Internal => ExitCode::OperationalError,
        };

        Self {
            code: err.code().to_string(),
            message: err.message().to_string(),
            exit_code,
            context: err
                .safe_context()
                .map(|s| serde_json::Value::String(s.to_string())),
        }
    }
}

impl From<StorageError> for CliError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::Corruption(reason) => Self {
                code: "ERR_STORAGE_CORRUPTION".to_string(),
                message: format!("Database corruption detected: {reason}"),
                exit_code: ExitCode::DegradedState,
                context: None,
            },
            StorageError::QuotaSaturated {
                current_bytes,
                max_bytes,
            } => Self {
                code: "ERR_STORAGE_QUOTA_SATURATED".to_string(),
                message: format!("Storage quota saturated: {current_bytes}/{max_bytes} bytes"),
                exit_code: ExitCode::DegradedState,
                context: Some(serde_json::json!({
                    "current_bytes": current_bytes,
                    "max_bytes": max_bytes,
                })),
            },
            other => Self {
                code: "ERR_STORAGE".to_string(),
                message: other.to_string(),
                exit_code: ExitCode::OperationalError,
                context: None,
            },
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        Self {
            code: "ERR_IO".to_string(),
            message: err.to_string(),
            exit_code: ExitCode::OperationalError,
            context: None,
        }
    }
}
