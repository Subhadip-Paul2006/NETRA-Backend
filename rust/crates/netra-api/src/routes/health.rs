use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::ToSchema;

use crate::errors::SuccessEnvelope;
use crate::state::AppState;

/// Health status payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HealthData {
    /// Overall service health state ("HEALTHY", "DEGRADED", or "FAILED").
    pub status: String,
    /// System uptime in seconds.
    pub uptime_seconds: u64,
    /// Individual component health reports.
    pub components: BTreeMap<String, String>,
}

/// GET /api/v1/health
/// Liveness probe and component health status.
#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "system",
    responses(
        (status = 200, description = "Service health status", body = SuccessEnvelope<HealthData>)
    )
)]
pub async fn get_health(State(state): State<AppState>) -> Json<SuccessEnvelope<HealthData>> {
    let mut components = BTreeMap::new();
    let coordinator_health = state.coordinator.health().await;

    let overall_status = match coordinator_health {
        netra_core::runtime::ComponentHealth::Healthy => "HEALTHY",
        netra_core::runtime::ComponentHealth::Degraded => "DEGRADED",
        netra_core::runtime::ComponentHealth::Failed => "FAILED",
    };

    components.insert("coordinator".to_string(), overall_status.to_string());

    let storage_status = match &state.storage {
        Some(storage) => match storage.state() {
            netra_core::storage::StorageState::Ready => "HEALTHY",
            netra_core::storage::StorageState::Degraded(_) => "DEGRADED",
            netra_core::storage::StorageState::Failed(_) => "FAILED",
            _ => "UNINITIALIZED",
        },
        None => "UNINITIALIZED",
    };
    components.insert("storage".to_string(), storage_status.to_string());

    let health_data = HealthData {
        status: overall_status.to_string(),
        uptime_seconds: state.uptime_seconds(),
        components,
    };

    Json(SuccessEnvelope::new(health_data))
}
