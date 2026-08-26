use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::errors::SuccessEnvelope;

pub const SCHEMA_VERSION: &str = "1.0";
pub const NETRA_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version metadata payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VersionData {
    /// REST API schema contract version.
    pub schema_version: String,
    /// Binary compilation version.
    pub netra_version: String,
    /// Target operating system family.
    pub target_os: String,
    /// Target architecture.
    pub target_arch: String,
    /// Compiler build profile.
    pub build_profile: String,
}

/// GET /api/v1/version
/// Application version, build profile, and schema contract metadata.
#[utoipa::path(
    get,
    path = "/api/v1/version",
    tag = "system",
    responses(
        (status = 200, description = "Application version metadata", body = SuccessEnvelope<VersionData>)
    )
)]
pub async fn get_version() -> impl IntoResponse {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    let version_data = VersionData {
        schema_version: SCHEMA_VERSION.to_string(),
        netra_version: NETRA_VERSION.to_string(),
        target_os: std::env::consts::OS.to_string(),
        target_arch: std::env::consts::ARCH.to_string(),
        build_profile: profile.to_string(),
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("public, max-age=3600"),
    );

    (headers, Json(SuccessEnvelope::new(version_data)))
}
