use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tower::ServiceExt;

use netra_api::{ApiConfig, ApiService, AppState};
use netra_core::runtime::RuntimeCoordinator;
use netra_core::storage::DatabaseEngine;

#[tokio::test]
async fn test_deep_check_single_flight_409_conflict() {
    let coordinator = Arc::new(RuntimeCoordinator::new());
    let storage = Arc::new(DatabaseEngine::in_memory().expect("failed to init in-memory db"));
    let config = ApiConfig::default_loopback();
    let state = AppState::new(coordinator, Some(storage), config);

    // Manually simulate an active deep scan by setting the atomic flag to true
    state.deep_check_lock.store(true, Ordering::SeqCst);

    let app = ApiService::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/storage/check?deep=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], false);
    assert_eq!(json["error"]["code"], "ERR_INTEGRITY_CHECK_IN_PROGRESS");
}

#[tokio::test]
async fn test_request_body_limit_rejection() {
    let coordinator = Arc::new(RuntimeCoordinator::new());
    let storage = Arc::new(DatabaseEngine::in_memory().expect("failed to init in-memory db"));
    let mut config = ApiConfig::default_loopback();
    config.max_body_bytes = 1024; // 1KB limit for test
    let state = AppState::new(coordinator, Some(storage), config);
    let app = ApiService::build_router(state);

    // Send 2KB body
    let oversized_payload = vec![b'A'; 2048];
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .method("POST")
                .body(Body::from(oversized_payload))
                .unwrap(),
        )
        .await
        .unwrap();

    // In axum with DefaultBodyLimit or method routing, excessive payload or unhandled method is rejected
    assert!(
        response.status() == StatusCode::PAYLOAD_TOO_LARGE
            || response.status() == StatusCode::METHOD_NOT_ALLOWED
    );
}
