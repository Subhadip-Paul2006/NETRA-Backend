use tokio_util::bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::error::{NetraError, Result};
use crate::ipc::protocol::{IpcEnvelope, MAX_IPC_FRAME_SIZE};

/// Codec for framing [`IpcEnvelope`] messages with a 4-byte big-endian length prefix.
#[derive(Debug, Default, Clone)]
pub struct IpcCodec {
    max_frame_size: usize,
}

impl IpcCodec {
    /// Creates a new codec with default maximum frame size (1MB).
    pub fn new() -> Self {
        Self {
            max_frame_size: MAX_IPC_FRAME_SIZE,
        }
    }

    /// Creates a new codec with a custom maximum frame size limit.
    pub fn with_max_frame_size(max_frame_size: usize) -> Self {
        Self { max_frame_size }
    }
}

impl Decoder for IpcCodec {
    type Item = IpcEnvelope;
    type Error = NetraError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        // Need at least 4 bytes for length header
        if src.len() < 4 {
            return Ok(None);
        }

        // Read 4-byte length prefix without consuming yet
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_be_bytes(length_bytes) as usize;

        // Enforce maximum frame size guard
        if length > self.max_frame_size {
            return Err(NetraError::runtime(format!(
                "IPC frame size ({} bytes) exceeds maximum limit ({} bytes)",
                length, self.max_frame_size
            )));
        }

        // Check if full frame payload is available
        if src.len() < 4 + length {
            // Wait for more bytes
            src.reserve(4 + length - src.len());
            return Ok(None);
        }

        // Consume length prefix
        src.advance(4);

        // Extract payload bytes
        let payload_bytes = src.split_to(length);

        // Deserialize JSON
        match serde_json::from_slice::<IpcEnvelope>(&payload_bytes) {
            Ok(envelope) => Ok(Some(envelope)),
            Err(err) => Err(NetraError::runtime(format!(
                "Malformed IPC JSON payload: {}",
                err
            ))),
        }
    }
}

impl Encoder<IpcEnvelope> for IpcCodec {
    type Error = NetraError;

    fn encode(&mut self, item: IpcEnvelope, dst: &mut BytesMut) -> Result<()> {
        let json_bytes = serde_json::to_vec(&item).map_err(|err| {
            NetraError::runtime(format!("Failed to serialize IPC envelope: {}", err))
        })?;

        let length = json_bytes.len();
        if length > self.max_frame_size {
            return Err(NetraError::runtime(format!(
                "Serialized IPC frame size ({} bytes) exceeds maximum limit ({} bytes)",
                length, self.max_frame_size
            )));
        }

        dst.reserve(4 + length);
        dst.put_u32(length as u32);
        dst.put_slice(&json_bytes);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::protocol::IpcPayload;

    #[test]
    fn test_ipc_codec_roundtrip() {
        let mut codec = IpcCodec::new();
        let payload = IpcPayload::Heartbeat {
            memory_rss_bytes: 1024 * 1024 * 20,
            cpu_usage_pct: 1.5,
            runtime_state: "RUNNING".to_string(),
            active_tasks: 2,
        };
        let envelope = IpcEnvelope::new(payload);

        let mut buffer = BytesMut::new();
        codec
            .encode(envelope.clone(), &mut buffer)
            .expect("encoding failed");

        assert!(buffer.len() > 4);

        let decoded = codec
            .decode(&mut buffer)
            .expect("decoding failed")
            .expect("expected complete message");

        assert_eq!(decoded, envelope);
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn test_ipc_codec_frame_overflow_rejected() {
        let mut codec = IpcCodec::with_max_frame_size(50);
        let payload = IpcPayload::ShutdownNotice {
            reason: "Detailed shutdown message that exceeds the small test limit easily"
                .to_string(),
            grace_period_ms: 5000,
        };
        let envelope = IpcEnvelope::new(payload);

        let mut buffer = BytesMut::new();
        let result = codec.encode(envelope, &mut buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipc_codec_partial_buffer_handling() {
        let mut codec = IpcCodec::new();
        let envelope = IpcEnvelope::new(IpcPayload::ShutdownAck);

        let mut full_buffer = BytesMut::new();
        codec
            .encode(envelope.clone(), &mut full_buffer)
            .expect("encode failed");

        // Provide partial bytes (e.g. only 3 bytes)
        let mut partial = full_buffer.split_to(3);
        assert!(codec.decode(&mut partial).unwrap().is_none());

        // Append rest of bytes
        partial.unsplit(full_buffer);
        let decoded = codec.decode(&mut partial).unwrap().unwrap();
        assert_eq!(decoded, envelope);
    }
}
