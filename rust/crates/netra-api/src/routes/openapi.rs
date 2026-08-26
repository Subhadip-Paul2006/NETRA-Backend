use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Json;

use crate::openapi::ApiDoc;
use utoipa::OpenApi;

/// GET /api/v1/openapi.json
/// Machine-readable OpenAPI 3.1 specification.
pub async fn get_openapi_json() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("public, max-age=3600"),
    );

    let doc = ApiDoc::openapi();
    (headers, Json(doc))
}
