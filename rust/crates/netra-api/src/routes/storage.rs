use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::Ordering;
use utoipa::{IntoParams, ToSchema};

use netra_core::storage::{
    ConfigRepository, FindingStatus, FindingsRepository, IntegrityVerification,
    ObservationQueueRepository, ObservationStatus, StorageQuotaManager,
};

use crate::errors::{ApiError, SuccessEnvelope};
use crate::state::AppState;

/// Table record counts payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StorageRecordCounts {
    pub migrations_applied: usize,
    pub config_entries: usize,
    pub queued_observations: usize,
    pub total_findings: usize,
}

/// Storage footprint and saturation status payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StorageStatusData {
    pub db_path: String,
    pub total_size_bytes: u64,
    pub db_size_bytes: u64,
    pub wal_size_bytes: u64,
    pub shm_size_bytes: u64,
    pub max_storage_bytes: u64,
    pub saturation_percent: f64,
    pub records: StorageRecordCounts,
}

/// Storage check query parameters.
#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct StorageCheckQuery {
    /// If true, executes Tier 3 deep integrity verification (integrity_check + foreign_key_check).
    /// If false (default), executes Tier 2 quick_check.
    pub deep: Option<bool>,
}

/// Storage integrity verification result payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StorageCheckData {
    pub db_path: String,
    pub tier: u8,
    pub check_type: String,
    pub duration_ms: u64,
    /// Boolean indicating whether the integrity probe passed cleanly without corruption.
    pub passed: bool,
    /// Diagnostic description or corruption findings.
    pub details: String,
}

/// GET /api/v1/storage/status
/// SQLite database disk footprint, WAL size, saturation %, and record counts.
#[utoipa::path(
    get,
    path = "/api/v1/storage/status",
    tag = "storage",
    responses(
        (status = 200, description = "Storage footprint status", body = SuccessEnvelope<StorageStatusData>),
        (status = 404, description = "Storage uninitialized")
    )
)]
pub async fn get_storage_status(
    State(state): State<AppState>,
) -> Result<Json<SuccessEnvelope<StorageStatusData>>, ApiError> {
    let storage = state
        .storage
        .as_ref()
        .ok_or_else(|| ApiError::NotFound("Storage engine is uninitialized".to_string()))?;

    let db_path_ref = storage.db_path();
    let db_path = db_path_ref.to_string_lossy().to_string();

    let parent_dir = db_path_ref.parent().unwrap_or_else(|| Path::new("."));
    let base_name = db_path_ref
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();

    let db_size = std::fs::metadata(db_path_ref).map(|m| m.len()).unwrap_or(0);
    let wal_size = std::fs::metadata(parent_dir.join(format!("{base_name}-wal")))
        .map(|m| m.len())
        .unwrap_or(0);
    let shm_size = std::fs::metadata(parent_dir.join(format!("{base_name}-shm")))
        .map(|m| m.len())
        .unwrap_or(0);
    let total_size = StorageQuotaManager::calculate_storage_bytes(db_path_ref);
    let max_storage = storage.max_storage_bytes();
    let saturation = if max_storage > 0 {
        (total_size as f64 / max_storage as f64) * 100.0
    } else {
        0.0
    };

    let records = storage
        .with_reader(|conn| {
            let migrations = conn
                .query_row("SELECT COUNT(*) FROM _netra_migrations", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap_or(0) as usize;

            let configs = ConfigRepository::list(conn).unwrap_or_default().len();
            let observations =
                ObservationQueueRepository::count_by_status(conn, ObservationStatus::Queued)
                    .unwrap_or(0) as usize;
            let findings = FindingsRepository::list_by_status(conn, FindingStatus::Open)
                .unwrap_or_default()
                .len();

            Ok(StorageRecordCounts {
                migrations_applied: migrations,
                config_entries: configs,
                queued_observations: observations,
                total_findings: findings,
            })
        })
        .await
        .map_err(ApiError::Storage)?;

    let status_data = StorageStatusData {
        db_path,
        total_size_bytes: total_size,
        db_size_bytes: db_size,
        wal_size_bytes: wal_size,
        shm_size_bytes: shm_size,
        max_storage_bytes: max_storage,
        saturation_percent: saturation,
        records,
    };

    Ok(Json(SuccessEnvelope::new(status_data)))
}

/// GET /api/v1/storage/check
/// Pure read-only SQLite integrity verification (Tier 2 quick_check or Tier 3 deep integrity_check).
#[utoipa::path(
    get,
    path = "/api/v1/storage/check",
    tag = "storage",
    params(StorageCheckQuery),
    responses(
        (status = 200, description = "Integrity check executed (see passed boolean)", body = SuccessEnvelope<StorageCheckData>),
        (status = 409, description = "Deep integrity check already in flight", body = crate::errors::ErrorEnvelope),
        (status = 503, description = "Storage engine unavailable", body = crate::errors::ErrorEnvelope)
    )
)]
pub async fn get_storage_check(
    State(state): State<AppState>,
    Query(query): Query<StorageCheckQuery>,
) -> Result<Json<SuccessEnvelope<StorageCheckData>>, ApiError> {
    let storage = state.storage.as_ref().ok_or_else(|| {
        ApiError::StorageUnavailable("Storage engine is uninitialized".to_string())
    })?;

    let is_deep = query.deep.unwrap_or(false);

    if is_deep {
        // Single-flight concurrency guard: acquire lock or reject with 409 Conflict
        if state
            .deep_check_lock
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(ApiError::Conflict(
                "A deep integrity check is already in progress. Concurrent scans are rejected to prevent I/O exhaustion.".to_string(),
            ));
        }

        struct LockGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for LockGuard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _guard = LockGuard(state.deep_check_lock.clone());

        let start = std::time::Instant::now();
        let check_result = storage
            .with_reader(IntegrityVerification::probe_tier3_deep_check)
            .await;
        let elapsed_ms = start.elapsed().as_millis() as u64;

        let db_path = storage.db_path().to_string_lossy().to_string();

        let check_data = match check_result {
            Ok(_) => StorageCheckData {
                db_path,
                tier: 3,
                check_type: "integrity_check + foreign_key_check".to_string(),
                duration_ms: elapsed_ms,
                passed: true,
                details: format!("Tier 3 deep check passed cleanly in {} ms", elapsed_ms),
            },
            Err(err) => StorageCheckData {
                db_path,
                tier: 3,
                check_type: "integrity_check + foreign_key_check".to_string(),
                duration_ms: elapsed_ms,
                passed: false,
                details: format!("Tier 3 integrity check detected corruption: {}", err),
            },
        };

        Ok(Json(SuccessEnvelope::new(check_data)))
    } else {
        let start = std::time::Instant::now();
        let check_result = storage
            .with_reader(IntegrityVerification::probe_tier2_quick_check)
            .await;
        let elapsed_ms = start.elapsed().as_millis() as u64;

        let db_path = storage.db_path().to_string_lossy().to_string();

        let check_data = match check_result {
            Ok(_) => StorageCheckData {
                db_path,
                tier: 2,
                check_type: "quick_check".to_string(),
                duration_ms: elapsed_ms,
                passed: true,
                details: format!("Tier 2 quick_check passed cleanly in {} ms", elapsed_ms),
            },
            Err(err) => StorageCheckData {
                db_path,
                tier: 2,
                check_type: "quick_check".to_string(),
                duration_ms: elapsed_ms,
                passed: false,
                details: format!("Tier 2 quick_check detected corruption: {}", err),
            },
        };

        Ok(Json(SuccessEnvelope::new(check_data)))
    }
}
