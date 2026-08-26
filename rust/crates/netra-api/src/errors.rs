use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use netra_core::error::NetraError;
use netra_core::storage::StorageError;

/// Universal error detail structure matching `docs/API.md` Section 4.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ErrorDetail {
    /// Machine-readable error code.
    pub code: String,
    /// Human-readable sanitized error description.
    pub message: String,
    /// Structured contextual details.
    pub details: serde_json::Value,
}

/// Universal request metadata envelope.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MetaEnvelope {
    /// Unique UUIDv7 request correlation identifier.
    pub request_id: String,
    /// ISO 8601 UTC timestamp.
    pub timestamp: String,
}

impl MetaEnvelope {
    pub fn new() -> Self {
        Self {
            request_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn with_request_id(request_id: String) -> Self {
        Self {
            request_id,
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

impl Default for MetaEnvelope {
    fn default() -> Self {
        Self::new()
    }
}

/// Universal success response envelope matching `docs/API.md` Section 4.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SuccessEnvelope<T> {
    /// Success indicator (always true).
    pub success: bool,
    /// Typed payload data.
    pub data: T,
    /// Request metadata.
    pub meta: MetaEnvelope,
}

impl<T> SuccessEnvelope<T> {
    pub fn new(data: T) -> Self {
        Self {
            success: true,
            data,
            meta: MetaEnvelope::new(),
        }
    }

    pub fn with_meta(data: T, meta: MetaEnvelope) -> Self {
        Self {
            success: true,
            data,
            meta,
        }
    }
}

/// Universal error response envelope matching `docs/API.md` Section 4.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ErrorEnvelope {
    /// Success indicator (always false).
    pub success: bool,
    /// Structured error information.
    pub error: ErrorDetail,
    /// Request metadata.
    pub meta: MetaEnvelope,
}

/// API Gateway Error taxonomy.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Invalid query parameters: {0}")]
    InvalidQuery(String),

    #[error("Request body exceeds maximum size limit (1MB)")]
    PayloadTooLarge,

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Resource conflict or operation already in progress: {0}")]
    Conflict(String),

    #[error("Unprocessable entity: {0}")]
    Unprocessable(String),

    #[error("Service is currently shutting down")]
    ServiceShuttingDown,

    #[error("Storage subsystem unavailable: {0}")]
    StorageUnavailable(String),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Core runtime error: {0}")]
    Core(#[from] NetraError),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl ApiError {
    /// Translates the API error into its standard HTTP status code.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidQuery(_) => StatusCode::BAD_REQUEST,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::ServiceShuttingDown => StatusCode::SERVICE_UNAVAILABLE,
            Self::StorageUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Storage(err) => match err {
                StorageError::QuotaSaturated { .. } | StorageError::EngineClosed => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
                StorageError::QuotaExceeded { .. } => StatusCode::INSUFFICIENT_STORAGE,
                StorageError::NotFound(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::Core(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Translates the API error into its machine-readable error code string.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidQuery(_) => "ERR_INVALID_QUERY_PARAMS",
            Self::PayloadTooLarge => "ERR_PAYLOAD_TOO_LARGE",
            Self::NotFound(_) => "ERR_NOT_FOUND",
            Self::Conflict(_) => "ERR_INTEGRITY_CHECK_IN_PROGRESS",
            Self::Unprocessable(_) => "ERR_UNPROCESSABLE_ENTITY",
            Self::ServiceShuttingDown => "ERR_SERVICE_SHUTTING_DOWN",
            Self::StorageUnavailable(_) => "ERR_STORAGE_UNAVAILABLE",
            Self::Storage(err) => match err {
                StorageError::QuotaSaturated { .. } => "ERR_STORAGE_SATURATED",
                StorageError::QuotaExceeded { .. } => "ERR_STORAGE_QUOTA_EXCEEDED",
                StorageError::Corruption(_) => "ERR_STORAGE_CORRUPTION",
                StorageError::EngineClosed => "ERR_STORAGE_CLOSED",
                _ => "ERR_STORAGE_FAILURE",
            },
            Self::Core(_) => "ERR_CORE_RUNTIME_FAILURE",
            Self::Internal(_) => "ERR_INTERNAL_SERVER_ERROR",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let envelope = ErrorEnvelope {
            success: false,
            error: ErrorDetail {
                code: self.error_code().to_string(),
                message: self.to_string(),
                details: serde_json::json!({}),
            },
            meta: MetaEnvelope::new(),
        };

        (status, Json(envelope)).into_response()
    }
}
