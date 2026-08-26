use netra_api::wss::{FrameType, WssClient, WssClientConfig};
use netra_core::identity::{DeviceId, DeviceKeypair, KeyId};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_wss_handshake_and_framing_lifecycle() {
    let dev_id = DeviceId::generate();
    let key_id = KeyId::generate();
    let keypair = Arc::new(DeviceKeypair::generate());

    let config = WssClientConfig {
        gateway_url: "wss://127.0.0.1:8443/api/v1/agent/stream".to_string(),
        ping_interval: Duration::from_secs(15),
        reconnect_base: Duration::from_secs(2),
        reconnect_max: Duration::from_secs(60),
        handshake_timeout: Duration::from_secs(10),
    };

    let client = WssClient::new(dev_id.clone(), key_id.clone(), keypair.clone(), config);

    // Verify initial state
    assert_eq!(client.session_id().await, None);

    // Verify handshake creation
    let challenge = "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6b";
    let handshake_frame = client.create_handshake_frame(challenge);

    assert_eq!(handshake_frame.frame_type, FrameType::SessionHandshakeReq);
    assert_eq!(handshake_frame.protocol_version, 1);
    assert_eq!(handshake_frame.device_id, dev_id);
    assert_eq!(handshake_frame.key_id.as_ref(), Some(&key_id));
    assert_eq!(handshake_frame.sequence_num, 0);
    assert!(handshake_frame.signature.is_some());

    // Verify ping frame has monotonic sequence numbers
    let ping1 = client.create_ping_frame().await;
    assert_eq!(ping1.frame_type, FrameType::HeartbeatPing);
    assert_eq!(ping1.sequence_num, 0);

    let ping2 = client.create_ping_frame().await;
    assert_eq!(ping2.sequence_num, 1);

    let ping3 = client.create_ping_frame().await;
    assert_eq!(ping3.sequence_num, 2);
}

#[test]
fn test_wss_backoff_jitter_bounds() {
    let base = Duration::from_secs(2);
    let max = Duration::from_secs(60);

    for attempt in 0..10 {
        let delay = WssClient::compute_backoff_delay(attempt, base, max);
        assert!(delay >= Duration::from_secs(2));
        assert!(delay <= Duration::from_millis(60500));
    }
}
