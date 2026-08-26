use netra_api::ApiDoc;
use utoipa::OpenApi;

#[test]
fn test_openapi_schema_generation() {
    let doc = ApiDoc::openapi();
    let json_str = serde_json::to_string_pretty(&doc).expect("failed to serialize OpenAPI schema");

    assert!(json_str.contains("/api/v1/health"));
    assert!(json_str.contains("/api/v1/version"));
    assert!(json_str.contains("/api/v1/status"));
    assert!(json_str.contains("/api/v1/diagnostics"));
    assert!(json_str.contains("/api/v1/storage/status"));
    assert!(json_str.contains("/api/v1/storage/check"));

    // Verify info block
    assert_eq!(doc.info.title, "NETRA Control-Plane REST API");
    assert_eq!(doc.info.version, "1.0.0");
}
