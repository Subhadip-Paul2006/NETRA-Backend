use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;

use netra_core::storage::repositories::findings::FindingsRepository;
use netra_core::storage::{FindingEntry, FindingSeverity, FindingStatus};

use crate::errors::{ApiError, SuccessEnvelope};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct FindingsQueryParams {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub limit: Option<usize>,
}

/// GET /api/v1/findings — Returns sanitized list of local security findings.
pub async fn get_findings(
    State(state): State<AppState>,
    Query(params): Query<FindingsQueryParams>,
) -> Result<Json<SuccessEnvelope<Vec<FindingEntry>>>, ApiError> {
    let engine = state
        .storage
        .as_ref()
        .ok_or_else(|| ApiError::NotFound("Storage engine is uninitialized".to_string()))?;

    let status_filter = if let Some(ref st) = params.status {
        Some(st.parse::<FindingStatus>().map_err(|_| {
            ApiError::InvalidQuery(format!(
                "Invalid finding status '{}'. Supported: OPEN, RESOLVED, SUPPRESSED",
                st
            ))
        })?)
    } else {
        None
    };

    let severity_filter = if let Some(ref sev) = params.severity {
        Some(sev.parse::<FindingSeverity>().map_err(|_| {
            ApiError::InvalidQuery(format!(
                "Invalid finding severity '{}'. Supported: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL",
                sev
            ))
        })?)
    } else {
        None
    };

    let findings = engine
        .with_reader(move |conn| {
            if let Some(status) = status_filter {
                FindingsRepository::list_by_status(conn, status)
            } else {
                FindingsRepository::list_all(conn)
            }
        })
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    let mut filtered_findings: Vec<FindingEntry> = findings
        .into_iter()
        .filter(|f| {
            if let Some(sev) = severity_filter {
                f.severity == sev
            } else {
                true
            }
        })
        .collect();

    if let Some(limit) = params.limit {
        if limit < filtered_findings.len() {
            filtered_findings.truncate(limit);
        }
    }

    Ok(Json(SuccessEnvelope::new(filtered_findings)))
}
