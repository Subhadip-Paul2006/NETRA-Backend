use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use netra_platform::detect_platform_info;

use crate::errors::SuccessEnvelope;
use crate::state::AppState;

/// System status payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StatusData {
    /// Runtime coordinator state machine state.
    pub state: String,
    /// System uptime in seconds.
    pub uptime_seconds: u64,
    /// Operating system platform family.
    pub platform: String,
    /// Operating system release/version string.
    pub os_version: String,
    /// Host computer name / hostname.
    pub hostname: String,
    /// CPU architecture.
    pub architecture: String,
    /// Storage subsystem state.
    pub storage_state: String,
}

/// GET /api/v1/status
/// Runtime coordinator state, platform info, and storage health.
#[utoipa::path(
    get,
    path = "/api/v1/status",
    tag = "system",
    responses(
        (status = 200, description = "System and runtime status", body = SuccessEnvelope<StatusData>)
    )
)]
pub async fn get_status(State(state): State<AppState>) -> Json<SuccessEnvelope<StatusData>> {
    let platform_info = detect_platform_info();
    let runtime_state = state.coordinator.state().await;

    let storage_state = match &state.storage {
        Some(storage) => match storage.state() {
            netra_core::storage::StorageState::Ready => "READY".to_string(),
            netra_core::storage::StorageState::Degraded(msg) => format!("DEGRADED: {}", msg),
            netra_core::storage::StorageState::Failed(msg) => format!("FAILED: {}", msg),
            netra_core::storage::StorageState::Uninitialized => "UNINITIALIZED".to_string(),
            netra_core::storage::StorageState::Stopping => "STOPPING".to_string(),
            netra_core::storage::StorageState::Stopped => "STOPPED".to_string(),
        },
        None => "UNINITIALIZED".to_string(),
    };

    let status_data = StatusData {
        state: runtime_state.to_string(),
        uptime_seconds: state.uptime_seconds(),
        platform: platform_info.os_family.to_string(),
        os_version: platform_info.os_version,
        hostname: platform_info.hostname,
        architecture: platform_info.arch,
        storage_state,
    };

    Json(SuccessEnvelope::new(status_data))
}
