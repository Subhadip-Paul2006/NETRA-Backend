use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

use netra_api::{ApiConfig, ApiService, AppState};
use netra_core::runtime::RuntimeCoordinator;
use netra_core::storage::DatabaseEngine;

async fn setup_test_app() -> (axum::Router, Arc<RuntimeCoordinator>, Arc<DatabaseEngine>) {
    let coordinator = Arc::new(RuntimeCoordinator::new());
    let storage = Arc::new(DatabaseEngine::in_memory().expect("failed to init in-memory db"));
    let config = ApiConfig::default_loopback();
    let state = AppState::new(coordinator.clone(), Some(storage.clone()), config);
    let app = ApiService::build_router(state);
    (app, coordinator, storage)
}

#[tokio::test]
async fn test_get_health() {
    let (app, _, _) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify headers
    assert!(response.headers().contains_key("x-request-id"));
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap(),
        "no-store, no-cache, must-revalidate"
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["data"]["status"], "HEALTHY");
    assert!(json["data"]["components"]["coordinator"].is_string());
    assert!(json["meta"]["request_id"].is_string());
    assert!(json["meta"]["timestamp"].is_string());
}

#[tokio::test]
async fn test_get_version() {
    let (app, _, _) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap(),
        "public, max-age=3600"
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["data"]["schema_version"], "1.0");
    assert_eq!(json["data"]["netra_version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn test_get_status() {
    let (app, _, _) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["data"]["state"], "CREATED");
    assert_eq!(json["data"]["storage_state"], "READY");
    assert!(!json["data"]["platform"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_get_diagnostics_sanitized() {
    let (app, _, _) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/diagnostics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["data"]["storage_initialized"], true);
    assert_eq!(json["data"]["storage_degraded"], false);
    assert_eq!(json["data"]["storage_configured"], true);

    // Verify data classification: strictly no raw passwords, keys, or env dumps
    assert!(json["data"].get("password").is_none());
    assert!(json["data"].get("secret").is_none());
    assert!(json["data"].get("token").is_none());
    assert!(json["data"].get("env").is_none());
}

#[tokio::test]
async fn test_get_storage_status() {
    let (app, _, _) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/storage/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert!(
        json["data"]["records"]["migrations_applied"]
            .as_u64()
            .unwrap()
            >= 1
    );
}

#[tokio::test]
async fn test_get_storage_check_quick_and_deep() {
    let (app, _, _) = setup_test_app().await;

    // Quick check (Tier 2 default)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/storage/check")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["success"], true);
    assert_eq!(json["data"]["tier"], 2);
    assert_eq!(json["data"]["passed"], true);

    // Deep check (Tier 3)
    let response_deep = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/storage/check?deep=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response_deep.status(), StatusCode::OK);
    let body_deep = response_deep
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let json_deep: Value = serde_json::from_slice(&body_deep).unwrap();
    assert_eq!(json_deep["success"], true);
    assert_eq!(json_deep["data"]["tier"], 3);
    assert_eq!(json_deep["data"]["passed"], true);
}
