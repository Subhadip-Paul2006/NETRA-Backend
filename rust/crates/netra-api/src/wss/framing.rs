use serde::{Deserialize, Serialize};
use serde_json::Value;

use netra_core::identity::{DeviceId, KeyId};

/// Non-speculative Phase 6 WSS frame types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FrameType {
    SessionHandshakeReq,
    SessionHandshakeResp,
    HeartbeatPing,
    HeartbeatPong,
    KeyRotationRequest,
    KeyRotationResp,
    DisconnectNotice,
}

/// Universal Canonical JSON WebSocket envelope for transport and security frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WssFrame {
    pub protocol_version: u32,
    pub frame_type: FrameType,
    pub device_id: DeviceId,
    pub key_id: Option<KeyId>,
    pub session_id: Option<String>,
    pub sequence_num: u64,
    pub timestamp: i64,
    pub payload: Value,
    pub signature: Option<String>,
}

impl WssFrame {
    /// Constructs a new WssFrame with protocol version 1.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        frame_type: FrameType,
        device_id: DeviceId,

        key_id: Option<KeyId>,
        session_id: Option<String>,
        sequence_num: u64,
        timestamp: i64,
        payload: Value,
        signature: Option<String>,
    ) -> Self {
        Self {
            protocol_version: 1,
            frame_type,
            device_id,
            key_id,
            session_id,
            sequence_num,
            timestamp,
            payload,
            signature,
        }
    }

    /// Serializes the frame to a JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parses a JSON string into a WssFrame.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_wss_frame_serialization_roundtrip() {
        let dev_id = DeviceId::generate();
        let key_id = KeyId::generate();
        let frame = WssFrame::new(
            FrameType::HeartbeatPing,
            dev_id.clone(),
            Some(key_id.clone()),
            Some("sess_01918a2b3c4d".to_string()),
            1,
            1776189500,
            json!({}),
            None,
        );

        let json_str = frame.to_json().unwrap();
        let parsed = WssFrame::from_json(&json_str).unwrap();

        assert_eq!(frame, parsed);
        assert_eq!(parsed.frame_type, FrameType::HeartbeatPing);
        assert_eq!(parsed.sequence_num, 1);
    }
}
