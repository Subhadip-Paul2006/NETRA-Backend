use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use netra_api::middleware::auth::{verify_request_signature, NonceCache};
use netra_core::identity::{CanonicalRequest, DeviceKeypair};

#[tokio::test]
async fn test_auth_signature_and_nonce_replay_mitigation() {
    let keypair = DeviceKeypair::generate();
    let cache = NonceCache::new(600);

    let method = "POST";
    let path = "/api/v1/storage/check";
    let timestamp = Utc::now().timestamp();
    let nonce = "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6b";
    let request_id = "req_01918a2b3c4d";
    let body = b"{\"deep\":true}";

    let canonical = CanonicalRequest::new(method, path, timestamp, nonce, request_id, body);
    let sig = canonical.sign(&keypair);

    let mut headers = HeaderMap::new();
    headers.insert(
        "x-netra-device-id",
        "dev_01918a2b3c4d7e8f9a0b1c2d3e4f5a6b".parse().unwrap(),
    );
    headers.insert("x-netra-timestamp", timestamp.to_string().parse().unwrap());
    headers.insert("x-netra-nonce", nonce.parse().unwrap());
    headers.insert("x-netra-request-id", request_id.parse().unwrap());
    headers.insert("x-netra-signature", sig.parse().unwrap());

    let bytes = Bytes::from_static(body);

    // First attempt: Must succeed
    let res1 = verify_request_signature(
        &headers,
        &bytes,
        method,
        path,
        keypair.verifying_key(),
        &cache,
    )
    .await;
    assert!(res1.is_ok());

    // Second attempt (Replay with same nonce): Must fail
    let res2 = verify_request_signature(
        &headers,
        &bytes,
        method,
        path,
        keypair.verifying_key(),
        &cache,
    )
    .await;
    assert!(res2.is_err());
    let (status, err_msg) = res2.unwrap_err();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(err_msg.contains("Replay attack detected"));
}

#[tokio::test]
async fn test_auth_clock_skew_mitigation() {
    let keypair = DeviceKeypair::generate();
    let cache = NonceCache::new(600);

    let method = "GET";
    let path = "/api/v1/status";
    // 310s in the future
    let future_timestamp = Utc::now().timestamp() + 310;
    let nonce = "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6c";
    let request_id = "req_01918a2b3c4e";
    let body = b"";

    let canonical = CanonicalRequest::new(method, path, future_timestamp, nonce, request_id, body);
    let sig = canonical.sign(&keypair);

    let mut headers = HeaderMap::new();
    headers.insert(
        "x-netra-device-id",
        "dev_01918a2b3c4d7e8f9a0b1c2d3e4f5a6b".parse().unwrap(),
    );
    headers.insert(
        "x-netra-timestamp",
        future_timestamp.to_string().parse().unwrap(),
    );
    headers.insert("x-netra-nonce", nonce.parse().unwrap());
    headers.insert("x-netra-request-id", request_id.parse().unwrap());
    headers.insert("x-netra-signature", sig.parse().unwrap());

    let bytes = Bytes::from_static(body);
    let res = verify_request_signature(
        &headers,
        &bytes,
        method,
        path,
        keypair.verifying_key(),
        &cache,
    )
    .await;

    assert!(res.is_err());
    let (status, err_msg) = res.unwrap_err();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(err_msg.contains("Clock skew exceeds 300 seconds limit"));
}
