use async_trait::async_trait;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use netra_core::error::NetraError;
use netra_core::ipc::protocol::IpcEnvelope;

/// Metadata describing an authenticated connecting peer process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCredentials {
    /// Process identifier (PID) of the peer process
    pub pid: Option<u32>,
    /// User identifier (UID) of the peer process on Unix platforms
    pub uid: Option<u32>,
}

/// Abstract stream capable of sending and receiving IPC envelopes.
#[async_trait]
pub trait IpcStream: Send + Sync + Unpin {
    /// Sends an IPC envelope over the stream.
    async fn send_envelope(&mut self, envelope: IpcEnvelope) -> Result<(), NetraError>;

    /// Receives the next IPC envelope from the stream, returning None on EOF.
    async fn recv_envelope(&mut self) -> Result<Option<IpcEnvelope>, NetraError>;
}

#[async_trait]
impl<T> IpcStream for T
where
    T: Stream<Item = Result<IpcEnvelope, NetraError>>
        + Sink<IpcEnvelope, Error = NetraError>
        + Send
        + Sync
        + Unpin,
{
    async fn send_envelope(&mut self, envelope: IpcEnvelope) -> Result<(), NetraError> {
        self.send(envelope).await
    }

    async fn recv_envelope(&mut self) -> Result<Option<IpcEnvelope>, NetraError> {
        match self.next().await {
            Some(res) => res.map(Some),
            None => Ok(None),
        }
    }
}

/// Platform-native Local IPC server interface.
#[async_trait]
pub trait IpcServer: Send + Sync + 'static {
    /// Descriptive name of the IPC transport.
    fn transport_name(&self) -> &'static str;

    /// Accepts the next incoming client connection, returning peer credentials and the stream.
    async fn accept(
        &mut self,
    ) -> Result<(Box<dyn IpcStream + 'static>, PeerCredentials), NetraError>;
}

/// Platform-native Local IPC client interface.
#[async_trait]
pub trait IpcClient: Send + Sync + 'static {
    /// Descriptive name of the IPC transport.
    fn transport_name(&self) -> &'static str;

    /// Connects to the local IPC endpoint and returns the framed stream.
    async fn connect(&self) -> Result<Box<dyn IpcStream + 'static>, NetraError>;
}
