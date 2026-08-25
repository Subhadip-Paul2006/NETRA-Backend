//! Platform-specific Local IPC server and client implementations.

pub mod traits;
#[cfg(not(target_os = "windows"))]
pub mod unix;
#[cfg(target_os = "windows")]
pub mod windows;

pub use traits::{IpcClient, IpcServer, IpcStream, PeerCredentials};

use netra_core::error::NetraError;

/// Returns the default platform-native IPC endpoint path or pipe name.
pub fn default_endpoint_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        windows::DEFAULT_WINDOWS_PIPE_NAME
    }

    #[cfg(not(target_os = "windows"))]
    {
        unix::DEFAULT_UNIX_SOCKET_PATH
    }
}

/// Creates and binds a platform-native IPC server.
pub fn create_ipc_server(endpoint_name: Option<&str>) -> Result<Box<dyn IpcServer>, NetraError> {
    let endpoint = endpoint_name.unwrap_or(default_endpoint_name());

    #[cfg(target_os = "windows")]
    {
        let server = windows::WindowsNamedPipeServer::bind(endpoint)?;
        Ok(Box::new(server))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let server = unix::UnixDomainSocketServer::bind(endpoint)?;
        Ok(Box::new(server))
    }
}

/// Creates a platform-native IPC client ready to connect.
pub fn create_ipc_client(endpoint_name: Option<&str>) -> Result<Box<dyn IpcClient>, NetraError> {
    let endpoint = endpoint_name.unwrap_or(default_endpoint_name());

    #[cfg(target_os = "windows")]
    {
        let client = windows::WindowsNamedPipeClient::new(endpoint);
        Ok(Box::new(client))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let client = unix::UnixDomainSocketClient::new(endpoint);
        Ok(Box::new(client))
    }
}
