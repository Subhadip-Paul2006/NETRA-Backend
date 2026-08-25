//! Worker runtime harness and IPC client state manager.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::error::{NetraError, Result};
use crate::ipc::protocol::{IpcEnvelope, IpcPayload};
use crate::lifecycle::RuntimeState;

/// State manager for the worker process IPC connection and lifecycle.
#[derive(Debug)]
pub struct WorkerHarness {
    token: String,
    session_id: Arc<RwLock<Option<String>>>,
    heartbeat_interval_ms: Arc<RwLock<u64>>,
    is_authenticated: Arc<AtomicBool>,
    is_running: Arc<AtomicBool>,
}

impl WorkerHarness {
    /// Creates a new worker harness configured with the provided startup token.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            session_id: Arc::new(RwLock::new(None)),
            heartbeat_interval_ms: Arc::new(RwLock::new(5000)),
            is_authenticated: Arc::new(AtomicBool::new(false)),
            is_running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Generates the initial handshake request envelope.
    pub fn create_handshake_request(&self) -> IpcEnvelope {
        let payload = IpcPayload::HandshakeRequest {
            token: self.token.clone(),
            client_pid: std::process::id(),
            client_role: "WORKER".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        IpcEnvelope::new(payload)
    }

    /// Handles the supervisor's handshake response.
    pub async fn handle_handshake_response(&self, envelope: &IpcEnvelope) -> Result<()> {
        match &envelope.payload {
            IpcPayload::HandshakeResponse {
                success,
                session_id,
                heartbeat_interval_ms,
                error,
            } => {
                if *success {
                    *self.session_id.write().await = session_id.clone();
                    if let Some(interval) = heartbeat_interval_ms {
                        *self.heartbeat_interval_ms.write().await = *interval;
                    }
                    self.is_authenticated.store(true, Ordering::SeqCst);
                    info!(
                        session_id = ?session_id,
                        "Worker successfully authenticated with supervisor"
                    );
                    Ok(())
                } else {
                    let err_msg = error.as_deref().unwrap_or("Handshake rejected");
                    error!(error = err_msg, "Worker authentication failed");
                    Err(NetraError::runtime(format!(
                        "Handshake failed: {}",
                        err_msg
                    )))
                }
            }
            _ => Err(NetraError::runtime(
                "Unexpected non-handshake response received",
            )),
        }
    }

    /// Creates a periodic telemetry heartbeat envelope.
    pub async fn create_heartbeat(
        &self,
        memory_rss_bytes: u64,
        cpu_usage_pct: f32,
        runtime_state: RuntimeState,
    ) -> Option<IpcEnvelope> {
        if !self.is_authenticated.load(Ordering::SeqCst) {
            return None;
        }

        let session_id = self.session_id.read().await.clone();
        let payload = IpcPayload::Heartbeat {
            memory_rss_bytes,
            cpu_usage_pct,
            runtime_state: runtime_state.to_string(),
            active_tasks: 0,
        };

        let mut env = IpcEnvelope::new(payload);
        env.session_id = session_id;
        Some(env)
    }

    /// Handles incoming commands and notices from the supervisor.
    pub async fn handle_incoming_message(&self, envelope: &IpcEnvelope) -> Option<IpcEnvelope> {
        match &envelope.payload {
            IpcPayload::ShutdownNotice {
                reason,
                grace_period_ms,
            } => {
                warn!(
                    reason = %reason,
                    grace_period_ms = grace_period_ms,
                    "Received shutdown notice from supervisor"
                );
                self.is_running.store(false, Ordering::SeqCst);
                Some(IpcEnvelope::response_to(envelope, IpcPayload::ShutdownAck))
            }
            IpcPayload::CommandRequest {
                command_id,
                command_name,
                ..
            } if command_name == "PING" => {
                let resp = IpcPayload::CommandResponse {
                    command_id: command_id.clone(),
                    success: true,
                    data: serde_json::json!({"status": "PONG"}),
                    error: None,
                };
                Some(IpcEnvelope::response_to(envelope, resp))
            }
            _ => None,
        }
    }

    /// Returns whether the worker should continue running.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }
}
