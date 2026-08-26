use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

pub const CACHE_CONTROL_HEADER: &str = "cache-control";
pub const NO_STORE_VALUE: &str = "no-store, no-cache, must-revalidate";

/// Middleware that injects Cache-Control: no-store on live diagnostic and state endpoints.
pub async fn no_cache_middleware(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;

    // Only inject no-store if Cache-Control was not explicitly set by the route handler
    if !response.headers().contains_key(CACHE_CONTROL_HEADER) {
        response.headers_mut().insert(
            CACHE_CONTROL_HEADER,
            HeaderValue::from_static(NO_STORE_VALUE),
        );
    }

    response
}
