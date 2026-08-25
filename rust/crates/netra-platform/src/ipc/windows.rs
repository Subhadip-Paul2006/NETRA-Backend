//! Windows Named Pipe IPC server and client implementation.

use async_trait::async_trait;
use netra_core::error::NetraError;
use netra_core::ipc::codec::IpcCodec;
use std::os::windows::io::AsRawHandle;
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use tokio_util::codec::Framed;
use tracing::{debug, info};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

use crate::ipc::traits::{IpcClient, IpcServer, IpcStream, PeerCredentials};

/// Default pipe name used on Windows.
pub const DEFAULT_WINDOWS_PIPE_NAME: &str = r"\\.\pipe\netra-supervisor-ipc";

/// Windows Named Pipe IPC Server.
pub struct WindowsNamedPipeServer {
    pipe_name: String,
    server: Option<NamedPipeServer>,
}

impl WindowsNamedPipeServer {
    /// Creates and binds a new Named Pipe server instance.
    pub fn bind(pipe_name: &str) -> Result<Self, NetraError> {
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(pipe_name)
            .map_err(|e| {
                NetraError::platform(format!(
                    "Failed to create initial Named Pipe '{}': {}",
                    pipe_name, e
                ))
            })?;

        info!(pipe_name = pipe_name, "Bound Windows Named Pipe IPC server");

        Ok(Self {
            pipe_name: pipe_name.to_string(),
            server: Some(server),
        })
    }
}

#[async_trait]
impl IpcServer for WindowsNamedPipeServer {
    fn transport_name(&self) -> &'static str {
        "Windows Named Pipe"
    }

    async fn accept(
        &mut self,
    ) -> Result<(Box<dyn IpcStream + 'static>, PeerCredentials), NetraError> {
        let current_server = self
            .server
            .take()
            .ok_or_else(|| NetraError::platform("Named Pipe server instance is not available"))?;

        current_server.connect().await.map_err(|e| {
            NetraError::platform(format!("Named Pipe client connect failed: {}", e))
        })?;

        // Query kernel for client PID
        let raw_handle = current_server.as_raw_handle() as HANDLE;
        let mut client_pid: u32 = 0;
        let ret = unsafe { GetNamedPipeClientProcessId(raw_handle, &mut client_pid) };
        let peer_pid = if ret != 0 {
            debug!(
                client_pid = client_pid,
                "Retrieved client PID from Named Pipe"
            );
            Some(client_pid)
        } else {
            None
        };

        // Prepare next server instance for subsequent connections
        let next_server = ServerOptions::new()
            .first_pipe_instance(false)
            .create(&self.pipe_name)
            .map_err(|e| {
                NetraError::platform(format!("Failed to recreate Named Pipe instance: {}", e))
            })?;
        self.server = Some(next_server);

        let framed = Framed::new(current_server, IpcCodec::new());
        let credentials = PeerCredentials {
            pid: peer_pid,
            uid: None,
        };

        Ok((Box::new(framed), credentials))
    }
}

/// Windows Named Pipe IPC Client.
pub struct WindowsNamedPipeClient {
    pipe_name: String,
}

impl WindowsNamedPipeClient {
    /// Creates a new Named Pipe client configured for the given pipe path.
    pub fn new(pipe_name: &str) -> Self {
        Self {
            pipe_name: pipe_name.to_string(),
        }
    }
}

#[async_trait]
impl IpcClient for WindowsNamedPipeClient {
    fn transport_name(&self) -> &'static str {
        "Windows Named Pipe"
    }

    async fn connect(&self) -> Result<Box<dyn IpcStream + 'static>, NetraError> {
        let client: NamedPipeClient = ClientOptions::new().open(&self.pipe_name).map_err(|e| {
            NetraError::platform(format!(
                "Failed to connect to Named Pipe '{}': {}",
                self.pipe_name, e
            ))
        })?;

        debug!(pipe_name = %self.pipe_name, "Connected to Windows Named Pipe IPC server");
        let framed = Framed::new(client, IpcCodec::new());
        Ok(Box::new(framed))
    }
}
