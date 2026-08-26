pub mod diagnostics;
pub mod health;
pub mod openapi;
pub mod status;
pub mod storage;
pub mod version;

use axum::routing::get;
use axum::Router;

use crate::state::AppState;

/// Creates the complete Axum router containing all versioned API routes.
pub fn create_router(state: AppState) -> Router {
    let api_v1 = Router::new()
        .route("/health", get(health::get_health))
        .route("/version", get(version::get_version))
        .route("/status", get(status::get_status))
        .route("/diagnostics", get(diagnostics::get_diagnostics))
        .route("/openapi.json", get(openapi::get_openapi_json))
        .route("/storage/status", get(storage::get_storage_status))
        .route("/storage/check", get(storage::get_storage_check));

    Router::new().nest("/api/v1", api_v1).with_state(state)
}
