//! Local Inter-Process Communication (IPC) domain protocol, framing, and authentication.

pub mod auth;
pub mod codec;
pub mod protocol;

pub use auth::{generate_ipc_token, verify_ipc_token};
pub use codec::IpcCodec;
pub use protocol::{IpcEnvelope, IpcPayload, IPC_PROTOCOL_VERSION, MAX_IPC_FRAME_SIZE};
