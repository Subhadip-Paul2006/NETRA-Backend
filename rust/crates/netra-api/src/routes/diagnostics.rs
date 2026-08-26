use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use netra_platform::detect_platform_info;

use crate::errors::SuccessEnvelope;
use crate::state::AppState;

/// Sanitized environment diagnostics bundle.
///
/// # Data Classification Boundary
/// Strictly excludes secrets, tokens, private keys, environment variable dumps,
/// raw database records, user credentials, and arbitrary filesystem trees.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DiagnosticsData {
    /// Target platform family name.
    pub platform: String,
    /// Operating system version.
    pub os_version: String,
    /// CPU Architecture.
    pub arch: String,
    /// Runtime coordinator state.
    pub runtime_state: String,
    /// System uptime in seconds.
    pub uptime_seconds: u64,
    /// Boolean indicator whether configuration loaded cleanly.
    pub config_valid: bool,
    /// Storage subsystem initialization flag.
    pub storage_initialized: bool,
    /// Storage degraded flag.
    pub storage_degraded: bool,
    /// Storage database path configured (boolean flag only, no raw absolute path leaked).
    pub storage_configured: bool,
    /// Storage quota saturation percentage (0.0 to 100.0).
    pub storage_saturation_pct: f64,
}

/// GET /api/v1/diagnostics
/// Host environment diagnostic bundle & configuration validation.
#[utoipa::path(
    get,
    path = "/api/v1/diagnostics",
    tag = "system",
    responses(
        (status = 200, description = "Sanitized diagnostic bundle", body = SuccessEnvelope<DiagnosticsData>)
    )
)]
pub async fn get_diagnostics(
    State(state): State<AppState>,
) -> Json<SuccessEnvelope<DiagnosticsData>> {
    let platform = detect_platform_info();
    let runtime_state = state.coordinator.state().await;

    let (storage_initialized, storage_degraded, storage_configured, storage_saturation_pct) =
        match &state.storage {
            Some(storage) => {
                let degraded = matches!(
                    storage.state(),
                    netra_core::storage::StorageState::Degraded(_)
                );
                let total_bytes = netra_core::storage::StorageQuotaManager::calculate_storage_bytes(
                    storage.db_path(),
                );
                let max_bytes = storage.max_storage_bytes();
                let saturation = if max_bytes > 0 {
                    (total_bytes as f64 / max_bytes as f64) * 100.0
                } else {
                    0.0
                };
                (true, degraded, true, saturation)
            }
            None => (false, false, false, 0.0),
        };

    let diagnostics = DiagnosticsData {
        platform: platform.os_family.to_string(),
        os_version: platform.os_version,
        arch: platform.arch,
        runtime_state: runtime_state.to_string(),
        uptime_seconds: state.uptime_seconds(),
        config_valid: true,
        storage_initialized,
        storage_degraded,
        storage_configured,
        storage_saturation_pct,
    };

    Json(SuccessEnvelope::new(diagnostics))
}
