use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::error::Result;
use crate::ipc::auth::generate_ipc_token;
use crate::ipc::protocol::{IpcEnvelope, IpcPayload};
use crate::supervisor::state::SupervisorState;
use crate::supervisor::watchdog::{CrashAction, CrashTracker, WatchdogPolicy};

/// Coordinates the supervisor lifecycle and active worker state.
#[derive(Debug)]
pub struct SupervisorEngine {
    state: Arc<RwLock<SupervisorState>>,
    policy: WatchdogPolicy,
    crash_tracker: Arc<RwLock<CrashTracker>>,
    current_token: Arc<RwLock<Option<String>>>,
    active_worker_pid: Arc<RwLock<Option<u32>>>,
    is_running: Arc<AtomicBool>,
}

impl SupervisorEngine {
    /// Creates a new supervisor engine instance with the given policy.
    pub fn new(policy: WatchdogPolicy) -> Self {
        Self {
            state: Arc::new(RwLock::new(SupervisorState::Starting)),
            policy,
            crash_tracker: Arc::new(RwLock::new(CrashTracker::new())),
            current_token: Arc::new(RwLock::new(None)),
            active_worker_pid: Arc::new(RwLock::new(None)),
            is_running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns the current supervisor lifecycle state.
    pub async fn state(&self) -> SupervisorState {
        *self.state.read().await
    }

    /// Generates and assigns a fresh 256-bit ephemeral token for the next worker instance.
    pub async fn prepare_next_worker_token(&self) -> String {
        let token = generate_ipc_token();
        *self.current_token.write().await = Some(token.clone());
        token
    }

    /// Returns the currently active expected worker token.
    pub async fn current_token(&self) -> Option<String> {
        self.current_token.read().await.clone()
    }

    /// Registers that a worker process has been spawned with `pid`.
    pub async fn register_worker_spawn(&self, pid: u32) {
        *self.active_worker_pid.write().await = Some(pid);
        let now = chrono::Utc::now().timestamp();
        self.crash_tracker.write().await.record_worker_start(now);
        info!(worker_pid = pid, "Registered newly spawned worker process");
    }

    /// Handles an incoming IPC envelope received by the supervisor.
    pub async fn handle_ipc_message(&self, envelope: IpcEnvelope) -> Option<IpcEnvelope> {
        let now = chrono::Utc::now().timestamp();

        match &envelope.payload {
            IpcPayload::HandshakeRequest {
                token,
                client_pid,
                version,
                ..
            } => {
                let expected = self.current_token.read().await;
                let is_valid = match expected.as_ref() {
                    Some(exp) => crate::ipc::auth::verify_ipc_token(exp, token),
                    None => false,
                };

                if is_valid {
                    let mut state = self.state.write().await;
                    let _ = state.transition_to(SupervisorState::Running);
                    info!(
                        client_pid = *client_pid,
                        client_version = %version,
                        "Worker authenticated successfully over IPC"
                    );

                    let session_id = uuid::Uuid::now_v7().to_string();
                    let resp = IpcPayload::HandshakeResponse {
                        success: true,
                        session_id: Some(session_id),
                        heartbeat_interval_ms: Some(self.policy.heartbeat_interval_ms),
                        error: None,
                    };
                    Some(IpcEnvelope::response_to(&envelope, resp))
                } else {
                    warn!(
                        client_pid = *client_pid,
                        "Rejected unauthorized worker handshake token"
                    );
                    let resp = IpcPayload::HandshakeResponse {
                        success: false,
                        session_id: None,
                        heartbeat_interval_ms: None,
                        error: Some("Invalid ephemeral handshake token".to_string()),
                    };
                    Some(IpcEnvelope::response_to(&envelope, resp))
                }
            }
            IpcPayload::Heartbeat {
                memory_rss_bytes,
                cpu_usage_pct,
                runtime_state,
                active_tasks,
            } => {
                self.crash_tracker
                    .write()
                    .await
                    .record_heartbeat(now, &self.policy);

                tracing::debug!(
                    memory_rss_mb = memory_rss_bytes / (1024 * 1024),
                    cpu_pct = cpu_usage_pct,
                    state = %runtime_state,
                    tasks = active_tasks,
                    "Received worker telemetry heartbeat"
                );

                let resp = IpcPayload::HeartbeatAck { timestamp: now };
                Some(IpcEnvelope::response_to(&envelope, resp))
            }
            IpcPayload::CommandRequest {
                ref command_id,
                ref command_name,
                ..
            } if command_name == "SUPERVISOR_STATUS" => {
                let current_state = *self.state.read().await;
                let active_pid = *self.active_worker_pid.read().await;
                let consecutive_crashes = self.crash_tracker.read().await.consecutive_crashes;

                let data = serde_json::json!({
                    "supervisor_state": current_state.to_string(),
                    "worker_pid": active_pid,
                    "consecutive_crashes": consecutive_crashes,
                });

                let resp = IpcPayload::CommandResponse {
                    command_id: command_id.clone(),
                    success: true,
                    data,
                    error: None,
                };
                Some(IpcEnvelope::response_to(&envelope, resp))
            }
            _ => None,
        }
    }

    /// Handles a detected worker process exit or crash event.
    pub async fn handle_worker_exit(&self, exit_code: Option<i32>) -> CrashAction {
        let now = chrono::Utc::now().timestamp();
        *self.active_worker_pid.write().await = None;

        warn!(
            exit_code = exit_code.unwrap_or(-1),
            "Worker process terminated"
        );

        let action = self
            .crash_tracker
            .write()
            .await
            .record_crash(now, &self.policy);

        match action {
            CrashAction::Restart { delay_ms } => {
                let mut state = self.state.write().await;
                let _ = state.transition_to(SupervisorState::Degraded);
                info!(
                    delay_ms = delay_ms,
                    "Scheduling automatic worker restart under watchdog policy"
                );
            }
            CrashAction::TripCircuitBreaker { total_crashes } => {
                let mut state = self.state.write().await;
                let _ = state.transition_to(SupervisorState::Failed);
                error!(
                    total_crashes = total_crashes,
                    "Worker crash threshold exceeded; circuit breaker tripped. Halting automatic restarts."
                );
            }
        }

        action
    }

    /// Initiates a graceful shutdown of the supervisor and worker.
    pub async fn shutdown(&self) -> Result<()> {
        let mut state = self.state.write().await;
        let _ = state.transition_to(SupervisorState::Stopping);
        self.is_running.store(false, Ordering::SeqCst);
        let _ = state.transition_to(SupervisorState::Stopped);
        info!("Supervisor shutdown completed");
        Ok(())
    }
}
