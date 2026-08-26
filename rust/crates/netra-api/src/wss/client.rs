use chrono::Utc;
use rand::Rng;
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use netra_core::identity::{DeviceId, DeviceKeypair, KeyId};

use crate::wss::framing::{FrameType, WssFrame};

/// Configuration options for the outbound WSS streaming client.
#[derive(Debug, Clone)]
pub struct WssClientConfig {
    pub gateway_url: String,
    pub ping_interval: Duration,
    pub reconnect_base: Duration,
    pub reconnect_max: Duration,
    pub handshake_timeout: Duration,
}

impl Default for WssClientConfig {
    fn default() -> Self {
        Self {
            gateway_url: "wss://127.0.0.1:8443/api/v1/agent/stream".to_string(),
            ping_interval: Duration::from_secs(15),
            reconnect_base: Duration::from_secs(2),
            reconnect_max: Duration::from_secs(60),
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

/// Outbound WebSocket over TLS 1.3 client managing session lifecycle, handshakes, and heartbeats.
pub struct WssClient {
    device_id: DeviceId,
    key_id: KeyId,
    keypair: Arc<DeviceKeypair>,
    config: WssClientConfig,
    sequence_num: AtomicU64,
    is_running: AtomicBool,
    active_session_id: Arc<Mutex<Option<String>>>,
}

impl WssClient {
    /// Creates a new WssClient instance.
    pub fn new(
        device_id: DeviceId,
        key_id: KeyId,
        keypair: Arc<DeviceKeypair>,
        config: WssClientConfig,
    ) -> Self {
        Self {
            device_id,
            key_id,
            keypair,
            config,
            sequence_num: AtomicU64::new(0),
            is_running: AtomicBool::new(false),
            active_session_id: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns a reference to the client configuration.
    pub fn config(&self) -> &WssClientConfig {
        &self.config
    }

    /// Computes exponential backoff delay with random jitter for reconnection attempts.
    pub fn compute_backoff_delay(attempt: u32, base: Duration, max: Duration) -> Duration {
        let base_millis = base.as_millis() as f64;
        let max_millis = max.as_millis() as f64;
        let factor = 2f64.powi(attempt.min(6) as i32);
        let exponential = (base_millis * factor).min(max_millis);

        // Add 0-500ms jitter
        let mut rng = rand::thread_rng();
        let jitter_ms: u64 = rng.gen_range(0..500);

        Duration::from_millis(exponential as u64 + jitter_ms)
    }

    /// Returns the current active session ID, if established.
    pub async fn session_id(&self) -> Option<String> {
        self.active_session_id.lock().await.clone()
    }

    /// Returns the next monotonic sequence number.
    pub fn next_sequence_num(&self) -> u64 {
        self.sequence_num.fetch_add(1, Ordering::SeqCst)
    }

    /// Constructs an authenticated session handshake frame.
    pub fn create_handshake_frame(&self, challenge_nonce: &str) -> WssFrame {
        let timestamp = Utc::now().timestamp();
        let mut frame = WssFrame::new(
            FrameType::SessionHandshakeReq,
            self.device_id.clone(),
            Some(self.key_id.clone()),
            None,
            0, // Handshake frame uses seq 0
            timestamp,
            json!({
                "challenge_nonce": challenge_nonce,
                "public_key_base64": self.keypair.public_key_base64()
            }),
            None,
        );

        // Sign the handshake
        let string_to_sign = format!(
            "SESSION_HANDSHAKE\n{}\n{}\n{}\n{}",
            self.device_id.as_str(),
            self.key_id.as_str(),
            challenge_nonce,
            timestamp
        );
        let sig = self.keypair.sign(string_to_sign.as_bytes());
        frame.signature = Some(hex::encode(sig.to_bytes()));
        frame
    }

    /// Constructs a heartbeat ping frame with monotonic sequence number.
    pub async fn create_ping_frame(&self) -> WssFrame {
        let session_id = self.session_id().await;
        WssFrame::new(
            FrameType::HeartbeatPing,
            self.device_id.clone(),
            Some(self.key_id.clone()),
            session_id,
            self.next_sequence_num(),
            Utc::now().timestamp(),
            json!({}),
            None, // Ping frames require no per-message signature
        )
    }

    /// Stops the client event loop.
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_computation() {
        let base = Duration::from_secs(2);
        let max = Duration::from_secs(60);

        let delay0 = WssClient::compute_backoff_delay(0, base, max);
        assert!(delay0 >= Duration::from_millis(2000));
        assert!(delay0 <= Duration::from_millis(2600));

        let delay3 = WssClient::compute_backoff_delay(3, base, max);
        assert!(delay3 >= Duration::from_millis(16000));
        assert!(delay3 <= Duration::from_millis(17000));
    }

    #[tokio::test]
    async fn test_handshake_and_ping_frame_creation() {
        let dev_id = DeviceId::generate();
        let key_id = KeyId::generate();
        let keypair = Arc::new(DeviceKeypair::generate());
        let client = WssClient::new(
            dev_id.clone(),
            key_id.clone(),
            keypair,
            WssClientConfig::default(),
        );

        let handshake = client.create_handshake_frame("test_nonce_123");
        assert_eq!(handshake.frame_type, FrameType::SessionHandshakeReq);
        assert!(handshake.signature.is_some());
        assert_eq!(handshake.sequence_num, 0);

        let ping = client.create_ping_frame().await;
        assert_eq!(ping.frame_type, FrameType::HeartbeatPing);
        assert_eq!(ping.sequence_num, 0);
        assert!(ping.signature.is_none());

        let ping2 = client.create_ping_frame().await;
        assert_eq!(ping2.sequence_num, 1);
    }
}
