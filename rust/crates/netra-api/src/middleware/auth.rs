use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use netra_core::identity::CanonicalRequest;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Sliding nonce cache for replay attack mitigation (600s TTL).
#[derive(Clone)]
pub struct NonceCache {
    entries: Arc<Mutex<HashMap<String, Instant>>>,
    ttl: Duration,
}

impl NonceCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Checks if a nonce was recently observed. If not, records it.
    ///
    /// Returns `true` if nonce is FRESH (accepted), `false` if REPLAYED (rejected).
    pub fn check_and_record(&self, nonce: &str) -> bool {
        let mut map = self.entries.lock().unwrap();
        let now = Instant::now();

        // Prune expired entries
        map.retain(|_, time| now.duration_since(*time) < self.ttl);

        if map.contains_key(nonce) {
            false
        } else {
            map.insert(nonce.to_string(), now);
            true
        }
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new(600)
    }
}

/// Validates Ed25519 signature and canonical request headers for authenticated endpoints.
pub async fn verify_request_signature(
    headers: &HeaderMap,
    body_bytes: &Bytes,
    method: &str,
    path: &str,
    public_key: &VerifyingKey,
    nonce_cache: &NonceCache,
) -> Result<(), (StatusCode, String)> {
    // 1. Extract required headers
    let device_id_str = headers
        .get("x-netra-device-id")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Missing X-NETRA-Device-ID header".to_string(),
        ))?;

    let timestamp_str = headers
        .get("x-netra-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Missing X-NETRA-Timestamp header".to_string(),
        ))?;

    let nonce_str = headers
        .get("x-netra-nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Missing X-NETRA-Nonce header".to_string(),
        ))?;

    let request_id_str = headers
        .get("x-netra-request-id")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Missing X-NETRA-Request-ID header".to_string(),
        ))?;

    let signature_str = headers
        .get("x-netra-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Missing X-NETRA-Signature header".to_string(),
        ))?;

    // 2. Validate timestamp skew (+-300s)
    let req_timestamp = timestamp_str.parse::<i64>().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid X-NETRA-Timestamp format".to_string(),
        )
    })?;

    let now_ts = Utc::now().timestamp();
    let skew = (now_ts - req_timestamp).abs();
    if skew > 300 {
        warn!("Rejected request with clock skew of {} seconds", skew);
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("Clock skew exceeds 300 seconds limit (skew: {}s)", skew),
        ));
    }

    // 3. Check nonce replay
    if !nonce_cache.check_and_record(nonce_str) {
        warn!("Rejected replayed nonce: {}", nonce_str);
        return Err((
            StatusCode::UNAUTHORIZED,
            "Replay attack detected: Nonce already used".to_string(),
        ));
    }

    // 4. Construct canonical request and verify signature
    let canonical = CanonicalRequest::new(
        method,
        path,
        req_timestamp,
        nonce_str,
        request_id_str,
        body_bytes,
    );

    canonical.verify(public_key, signature_str).map_err(|e| {
        warn!("Signature verification failed for {}: {}", device_id_str, e);
        (
            StatusCode::UNAUTHORIZED,
            format!("Cryptographic signature verification failed: {}", e),
        )
    })?;

    debug!(
        "Verified canonical signature for device '{}'",
        device_id_str
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netra_core::identity::DeviceKeypair;

    #[test]
    fn test_nonce_cache_replay_detection() {
        let cache = NonceCache::new(600);
        let nonce = "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6b";

        assert!(cache.check_and_record(nonce));
        // Replayed nonce must return false
        assert!(!cache.check_and_record(nonce));
    }

    #[tokio::test]
    async fn test_verify_request_signature_success() {
        let keypair = DeviceKeypair::generate();
        let cache = NonceCache::new(600);

        let method = "POST";
        let path = "/api/v1/storage/check";
        let timestamp = Utc::now().timestamp();
        let nonce = "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6b";
        let request_id = "req_01918a2b3c4d";
        let body = b"{\"deep\":false}";

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
        let res = verify_request_signature(
            &headers,
            &bytes,
            method,
            path,
            keypair.verifying_key(),
            &cache,
        )
        .await;

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_verify_request_clock_skew_rejection() {
        let keypair = DeviceKeypair::generate();
        let cache = NonceCache::new(600);

        let method = "GET";
        let path = "/api/v1/status";
        let stale_timestamp = Utc::now().timestamp() - 305; // 305 seconds old
        let nonce = "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6c";
        let request_id = "req_01918a2b3c4e";
        let body = b"";

        let canonical =
            CanonicalRequest::new(method, path, stale_timestamp, nonce, request_id, body);
        let sig = canonical.sign(&keypair);

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-netra-device-id",
            "dev_01918a2b3c4d7e8f9a0b1c2d3e4f5a6b".parse().unwrap(),
        );
        headers.insert(
            "x-netra-timestamp",
            stale_timestamp.to_string().parse().unwrap(),
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
        let (status, msg) = res.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(msg.contains("Clock skew exceeds 300 seconds limit"));
    }
}
