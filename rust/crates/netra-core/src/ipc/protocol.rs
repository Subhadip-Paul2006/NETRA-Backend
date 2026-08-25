//! Internal Local IPC Protocol schema definitions and envelope models.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Current supported IPC protocol version.
pub const IPC_PROTOCOL_VERSION: u32 = 1;

/// Maximum payload size in bytes for a single frame (1MB).
pub const MAX_IPC_FRAME_SIZE: usize = 1024 * 1024;

/// Standard universal envelope for all local IPC communication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IpcEnvelope {
    /// Protocol version identifier
    pub protocol_version: u32,
    /// Message type identifier (e.g. "HandshakeRequest", "Heartbeat")
    pub message_type: String,
    /// Unique message request identifier (UUIDv7)
    pub request_id: String,
    /// Optional correlation ID linking response to a request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Optional authenticated session token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Epoch timestamp in seconds
    pub timestamp: i64,
    /// Type-specific message payload
    pub payload: IpcPayload,
}

impl IpcEnvelope {
    /// Creates a new IPC envelope wrapping the given payload.
    pub fn new(payload: IpcPayload) -> Self {
        let message_type = payload.type_name().to_string();
        Self {
            protocol_version: IPC_PROTOCOL_VERSION,
            message_type,
            request_id: Uuid::now_v7().to_string(),
            correlation_id: None,
            session_id: None,
            timestamp: chrono::Utc::now().timestamp(),
            payload,
        }
    }

    /// Creates a correlated response envelope responding to `req`.
    pub fn response_to(req: &IpcEnvelope, payload: IpcPayload) -> Self {
        let message_type = payload.type_name().to_string();
        Self {
            protocol_version: IPC_PROTOCOL_VERSION,
            message_type,
            request_id: Uuid::now_v7().to_string(),
            correlation_id: Some(req.request_id.clone()),
            session_id: req.session_id.clone(),
            timestamp: chrono::Utc::now().timestamp(),
            payload,
        }
    }

    /// Associates an authenticated session ID with the envelope.
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }
}

/// Typed payloads supported across the local IPC protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", content = "data")]
pub enum IpcPayload {
    /// Initial client handshake request presenting token and PID
    HandshakeRequest {
        token: String,
        client_pid: u32,
        client_role: String,
        version: String,
    },
    /// Response to handshake request
    HandshakeResponse {
        success: bool,
        session_id: Option<String>,
        heartbeat_interval_ms: Option<u64>,
        error: Option<String>,
    },
    /// Periodic worker telemetry heartbeat
    Heartbeat {
        memory_rss_bytes: u64,
        cpu_usage_pct: f32,
        runtime_state: String,
        active_tasks: u32,
    },
    /// Acknowledgment of heartbeat
    HeartbeatAck { timestamp: i64 },
    /// Command dispatched from supervisor/CLI to worker
    CommandRequest {
        command_id: String,
        command_name: String,
        parameters: serde_json::Value,
    },
    /// Result of command execution returned by worker
    CommandResponse {
        command_id: String,
        success: bool,
        data: serde_json::Value,
        error: Option<String>,
    },
    /// Graceful shutdown notification dispatched before process exit
    ShutdownNotice {
        reason: String,
        grace_period_ms: u64,
    },
    /// Acknowledgment of shutdown notice
    ShutdownAck,
    /// Protocol error response
    ErrorResponse { error_code: String, message: String },
}

impl IpcPayload {
    /// Returns the canonical type name for the payload.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::HandshakeRequest { .. } => "HandshakeRequest",
            Self::HandshakeResponse { .. } => "HandshakeResponse",
            Self::Heartbeat { .. } => "Heartbeat",
            Self::HeartbeatAck { .. } => "HeartbeatAck",
            Self::CommandRequest { .. } => "CommandRequest",
            Self::CommandResponse { .. } => "CommandResponse",
            Self::ShutdownNotice { .. } => "ShutdownNotice",
            Self::ShutdownAck => "ShutdownAck",
            Self::ErrorResponse { .. } => "ErrorResponse",
        }
    }
}

impl fmt::Display for IpcPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.type_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_creation_and_serialization() {
        let payload = IpcPayload::HandshakeRequest {
            token: "secret123".to_string(),
            client_pid: 4080,
            client_role: "WORKER".to_string(),
            version: "1.0.0-foundation".to_string(),
        };

        let env = IpcEnvelope::new(payload);
        assert_eq!(env.protocol_version, IPC_PROTOCOL_VERSION);
        assert_eq!(env.message_type, "HandshakeRequest");
        assert!(env.session_id.is_none());

        let json_str = serde_json::to_string(&env).expect("serialization failed");
        let deserialized: IpcEnvelope =
            serde_json::from_str(&json_str).expect("deserialization failed");

        assert_eq!(env, deserialized);
    }

    #[test]
    fn test_envelope_response_correlation() {
        let req_payload = IpcPayload::CommandRequest {
            command_id: "cmd_01".to_string(),
            command_name: "STATUS_QUERY".to_string(),
            parameters: serde_json::json!({}),
        };
        let req = IpcEnvelope::new(req_payload).with_session_id("sess_test");

        let resp_payload = IpcPayload::CommandResponse {
            command_id: "cmd_01".to_string(),
            success: true,
            data: serde_json::json!({"state": "RUNNING"}),
            error: None,
        };

        let resp = IpcEnvelope::response_to(&req, resp_payload);
        assert_eq!(resp.correlation_id, Some(req.request_id.clone()));
        assert_eq!(resp.session_id, Some("sess_test".to_string()));
        assert_eq!(resp.message_type, "CommandResponse");
    }
}
