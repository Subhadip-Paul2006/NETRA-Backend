//! # JSON Envelope Models (`netra-cli::output::envelope`)
//!
//! Strongly-typed, versioned JSON envelopes emitted to `stdout` during `--json` execution.

use chrono::Utc;
use serde::Serialize;

use crate::version::{NETRA_VERSION, SCHEMA_VERSION};

/// Universal success response envelope for machine-readable CLI outputs.
#[derive(Debug, Clone, Serialize)]
pub struct JsonSuccessEnvelope<'a, T: Serialize> {
    /// Canonical JSON schema contract version.
    pub schema_version: &'static str,
    /// NETRA application release version.
    pub netra_version: &'static str,
    /// Command that generated this response (e.g., "status", "storage status").
    pub command: &'a str,
    /// Execution status: always "success" for successful envelopes.
    pub status: &'static str,
    /// Structured response payload.
    pub data: &'a T,
    /// Deterministic UTC timestamp in RFC3339 format.
    pub timestamp: String,
}

impl<'a, T: Serialize> JsonSuccessEnvelope<'a, T> {
    pub fn new(command: &'a str, data: &'a T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            netra_version: NETRA_VERSION,
            command,
            status: "success",
            data,
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

/// Structured error payload embedded inside error envelopes.
#[derive(Debug, Clone, Serialize)]
pub struct JsonErrorPayload<'a> {
    pub code: &'a str,
    pub message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<&'a serde_json::Value>,
}

/// Universal error response envelope for machine-readable CLI outputs.
#[derive(Debug, Clone, Serialize)]
pub struct JsonErrorEnvelope<'a> {
    /// Canonical JSON schema contract version.
    pub schema_version: &'static str,
    /// NETRA application release version.
    pub netra_version: &'static str,
    /// Command that failed.
    pub command: &'a str,
    /// Execution status: always "error" for error envelopes.
    pub status: &'static str,
    /// Detailed error payload.
    pub error: JsonErrorPayload<'a>,
    /// Deterministic UTC timestamp in RFC3339 format.
    pub timestamp: String,
}

impl<'a> JsonErrorEnvelope<'a> {
    pub fn new(
        command: &'a str,
        code: &'a str,
        message: &'a str,
        context: Option<&'a serde_json::Value>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            netra_version: NETRA_VERSION,
            command,
            status: "error",
            error: JsonErrorPayload {
                code,
                message,
                context,
            },
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}
