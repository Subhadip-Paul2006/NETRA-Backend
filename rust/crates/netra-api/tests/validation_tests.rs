use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

use netra_api::{ApiConfig, ApiService, AppState};
use netra_core::runtime::RuntimeCoordinator;
use netra_core::storage::DatabaseEngine;

#[test]
fn test_loopback_validation_policy() {
    // Valid loopback configurations
    let ipv4_loopback = ApiConfig {
        host: "127.0.0.1".to_string(),
        port: 8443,
        request_timeout_secs: 15,
        max_body_bytes: 1024 * 1024,
    };
    assert!(ipv4_loopback.validate().is_ok());

    let ipv6_loopback = ApiConfig {
        host: "::1".to_string(),
        port: 8443,
        request_timeout_secs: 15,
        max_body_bytes: 1024 * 1024,
    };
    assert!(ipv6_loopback.validate().is_ok());

    // Invalid non-loopback bindings (must fail validation)
    let public_wildcard = ApiConfig {
        host: "0.0.0.0".to_string(),
        port: 8443,
        request_timeout_secs: 15,
        max_body_bytes: 1024 * 1024,
    };
    assert!(public_wildcard.validate().is_err());

    let lan_ip = ApiConfig {
        host: "192.168.1.50".to_string(),
        port: 8443,
        request_timeout_secs: 15,
        max_body_bytes: 1024 * 1024,
    };
    assert!(lan_ip.validate().is_err());

    let public_ip = ApiConfig {
        host: "8.8.8.8".to_string(),
        port: 8443,
        request_timeout_secs: 15,
        max_body_bytes: 1024 * 1024,
    };
    assert!(public_ip.validate().is_err());
}

#[tokio::test]
async fn test_unknown_route_returns_404() {
    let coordinator = Arc::new(RuntimeCoordinator::new());
    let storage = Arc::new(DatabaseEngine::in_memory().expect("failed to init in-memory db"));
    let config = ApiConfig::default_loopback();
    let state = AppState::new(coordinator, Some(storage), config);
    let app = ApiService::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/non_existent_route")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_invalid_query_param_handling() {
    let coordinator = Arc::new(RuntimeCoordinator::new());
    let storage = Arc::new(DatabaseEngine::in_memory().expect("failed to init in-memory db"));
    let config = ApiConfig::default_loopback();
    let state = AppState::new(coordinator, Some(storage), config);
    let app = ApiService::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/storage/check?deep=not_a_boolean")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Query extractor rejection returns 400 Bad Request or 422 Unprocessable Entity
    assert!(
        response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY
    );
}
