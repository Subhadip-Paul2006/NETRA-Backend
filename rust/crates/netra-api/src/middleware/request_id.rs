use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Middleware that injects or propagates a UUIDv7 request correlation ID across request and response headers.
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let request_id = match req.headers().get(REQUEST_ID_HEADER) {
        Some(val) => val
            .to_str()
            .ok()
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::now_v7().to_string()),
        None => Uuid::now_v7().to_string(),
    };

    if let Ok(header_val) = HeaderValue::from_str(&request_id) {
        req.headers_mut().insert(REQUEST_ID_HEADER, header_val);
    }

    req.extensions_mut().insert(request_id.clone());

    let mut response = next.run(req).await;

    if let Ok(header_val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, header_val);
    }

    response
}
