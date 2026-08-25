//! Integration tests verifying Local IPC protocol framing, authentication, and lifecycle.

use netra_core::error::Result;
use netra_core::ipc::auth::{generate_ipc_token, verify_ipc_token};
use netra_core::ipc::codec::IpcCodec;
use netra_core::ipc::protocol::{IpcEnvelope, IpcPayload, IPC_PROTOCOL_VERSION};
use netra_core::supervisor::{SupervisorEngine, WatchdogPolicy};
use netra_core::worker::WorkerHarness;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Encoder;

#[tokio::test]
async fn test_full_ipc_handshake_authentication_flow() -> Result<()> {
    let policy = WatchdogPolicy::default();
    let supervisor = SupervisorEngine::new(policy);

    // Supervisor prepares an ephemeral token for the spawned worker
    let token = supervisor.prepare_next_worker_token().await;
    supervisor.register_worker_spawn(4242).await;

    // Worker creates handshake request presenting the token
    let worker = WorkerHarness::new(token);
    let handshake_req = worker.create_handshake_request();

    // Supervisor handles handshake
    let resp = supervisor
        .handle_ipc_message(handshake_req)
        .await
        .expect("expected handshake response");

    // Worker handles handshake response
    worker.handle_handshake_response(&resp).await?;

    // Verify supervisor state is now Running
    assert_eq!(
        supervisor.state().await,
        netra_core::supervisor::SupervisorState::Running
    );

    Ok(())
}

#[tokio::test]
async fn test_ipc_handshake_rejected_on_invalid_token() {
    let policy = WatchdogPolicy::default();
    let supervisor = SupervisorEngine::new(policy);

    let _valid_token = supervisor.prepare_next_worker_token().await;

    // Worker configured with an invalid/forged token
    let rogue_worker = WorkerHarness::new("forged_unauthorized_token_12345");
    let handshake_req = rogue_worker.create_handshake_request();

    let resp = supervisor
        .handle_ipc_message(handshake_req)
        .await
        .expect("expected response");

    let result = rogue_worker.handle_handshake_response(&resp).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Handshake failed"));
}

#[tokio::test]
async fn test_ipc_frame_size_overflow_guard() {
    let mut codec = IpcCodec::with_max_frame_size(100);

    let large_payload = IpcPayload::ShutdownNotice {
        reason: "This is an excessively long notice string designed to exceed the 100-byte test guard ceiling".to_string(),
        grace_period_ms: 5000,
    };
    let env = IpcEnvelope::new(large_payload);

    let mut buf = BytesMut::new();
    let encode_res = codec.encode(env, &mut buf);
    assert!(encode_res.is_err());
    assert!(encode_res
        .unwrap_err()
        .to_string()
        .contains("exceeds maximum limit"));
}

#[tokio::test]
async fn test_ipc_heartbeat_and_telemetry_flow() {
    let policy = WatchdogPolicy::default();
    let supervisor = SupervisorEngine::new(policy);
    let token = supervisor.prepare_next_worker_token().await;

    let worker = WorkerHarness::new(token);
    let handshake_req = worker.create_handshake_request();
    let resp = supervisor.handle_ipc_message(handshake_req).await.unwrap();
    worker.handle_handshake_response(&resp).await.unwrap();

    // Worker creates telemetry heartbeat
    let heartbeat = worker
        .create_heartbeat(
            15 * 1024 * 1024,
            0.5,
            netra_core::runtime::RuntimeState::Running,
        )
        .await
        .expect("expected heartbeat envelope");

    let ack = supervisor
        .handle_ipc_message(heartbeat)
        .await
        .expect("expected heartbeat ack");

    assert_eq!(ack.protocol_version, IPC_PROTOCOL_VERSION);
    assert!(matches!(ack.payload, IpcPayload::HeartbeatAck { .. }));
}

#[tokio::test]
async fn test_ipc_shutdown_notice_and_ack() {
    let worker = WorkerHarness::new("token123");
    let notice = IpcEnvelope::new(IpcPayload::ShutdownNotice {
        reason: "SIGINT".to_string(),
        grace_period_ms: 3000,
    });

    let ack = worker
        .handle_incoming_message(&notice)
        .await
        .expect("expected shutdown ack");

    assert_eq!(ack.payload, IpcPayload::ShutdownAck);
    assert!(!worker.is_running());
}

#[test]
fn test_constant_time_token_verification() {
    let token = generate_ipc_token();
    assert!(verify_ipc_token(&token, &token));
    assert!(!verify_ipc_token(&token, "invalid"));
}
