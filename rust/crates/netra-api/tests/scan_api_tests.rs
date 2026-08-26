use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use netra_api::config::ApiConfig;
use netra_api::routes::create_router;
use netra_api::state::AppState;
use netra_core::runtime::RuntimeCoordinator;
use netra_core::storage::repositories::findings::FindingsRepository;
use netra_core::storage::{DatabaseEngine, FindingSeverity};

#[tokio::test]
async fn test_scan_and_findings_rest_endpoints() {
    let coordinator = Arc::new(RuntimeCoordinator::new());
    let storage = Arc::new(DatabaseEngine::in_memory().unwrap());

    // Insert a sample finding
    storage
        .with_writer(|conn| {
            FindingsRepository::upsert(
                conn,
                "NET-001-PLAINTEXT-PORT",
                FindingSeverity::High,
                "socket:tcp:0.0.0.0:80",
                "0.0.0.0:80",
                "Unencrypted Plaintext Service",
                "{\"evidence\":\"port 80\"}",
            )
        })
        .await
        .unwrap();

    let api_config = ApiConfig::default();
    let state = AppState::new(coordinator, Some(storage), api_config);
    let app = create_router(state);

    // 1. Test GET /api/v1/scan/status
    let req = Request::builder()
        .uri("/api/v1/scan/status")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["data"]["total_open_findings"], 1);

    // 2. Test GET /api/v1/findings
    let req2 = Request::builder()
        .uri("/api/v1/findings?status=OPEN")
        .body(axum::body::Body::empty())
        .unwrap();

    let response2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(response2.status(), StatusCode::OK);

    let bytes2 = to_bytes(response2.into_body(), usize::MAX).await.unwrap();
    let body2: serde_json::Value = serde_json::from_slice(&bytes2).unwrap();
    assert_eq!(body2["data"].as_array().unwrap().len(), 1);
    assert_eq!(body2["data"][0]["rule_id"], "NET-001-PLAINTEXT-PORT");
}
