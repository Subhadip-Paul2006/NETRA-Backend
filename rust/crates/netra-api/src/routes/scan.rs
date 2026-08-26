use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use netra_core::storage::repositories::findings::FindingsRepository;
use netra_core::storage::repositories::queue::ObservationQueueRepository;
use netra_core::storage::{FindingStatus, ObservationStatus};

use crate::errors::{ApiError, SuccessEnvelope};
use crate::state::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatusResponse {
    pub total_open_findings: i64,
    pub total_queued_observations: i64,
    pub loopback_diagnostic: bool,
}

/// GET /api/v1/scan/status — Returns high-level scan posture status.
pub async fn get_scan_status(
    State(state): State<AppState>,
) -> Result<Json<SuccessEnvelope<ScanStatusResponse>>, ApiError> {
    let engine = state
        .storage
        .as_ref()
        .ok_or_else(|| ApiError::NotFound("Storage engine is uninitialized".to_string()))?;

    let total_open_findings = engine
        .with_reader(|conn| FindingsRepository::count_by_status(conn, FindingStatus::Open))
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    let total_queued_observations = engine
        .with_reader(|conn| {
            ObservationQueueRepository::count_by_status(conn, ObservationStatus::Queued)
        })
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    let res = ScanStatusResponse {
        total_open_findings,
        total_queued_observations,
        loopback_diagnostic: true,
    };

    Ok(Json(SuccessEnvelope::new(res)))
}
