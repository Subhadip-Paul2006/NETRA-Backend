use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::time::Duration;

use crate::errors::{ErrorDetail, ErrorEnvelope, MetaEnvelope};

/// Middleware enforcing request execution timeout.
pub async fn timeout_middleware(req: Request, next: Next, timeout_duration: Duration) -> Response {
    match tokio::time::timeout(timeout_duration, next.run(req)).await {
        Ok(response) => response,
        Err(_) => {
            let envelope = ErrorEnvelope {
                success: false,
                error: ErrorDetail {
                    code: "ERR_REQUEST_TIMEOUT".to_string(),
                    message: format!(
                        "Request execution timed out after {} seconds",
                        timeout_duration.as_secs()
                    ),
                    details: serde_json::json!({}),
                },
                meta: MetaEnvelope::new(),
            };
            (StatusCode::GATEWAY_TIMEOUT, Json(envelope)).into_response()
        }
    }
}
