//! Unix Domain Socket IPC server and client implementation.

use async_trait::async_trait;
use netra_core::error::NetraError;
use netra_core::ipc::codec::IpcCodec;
use std::path::{Path, PathBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::Framed;
use tracing::{debug, info};

use crate::ipc::traits::{IpcClient, IpcServer, IpcStream, PeerCredentials};

/// Default Unix domain socket path.
pub const DEFAULT_UNIX_SOCKET_PATH: &str = "/run/netra/supervisor.sock";

/// Unix Domain Socket IPC Server.
pub struct UnixDomainSocketServer {
    socket_path: PathBuf,
    listener: UnixListener,
}

impl UnixDomainSocketServer {
    /// Creates and binds a new Unix Domain Socket server, setting permissions to 0600.
    pub fn bind<P: AsRef<Path>>(socket_path: P) -> Result<Self, NetraError> {
        let path = socket_path.as_ref().to_path_buf();

        // Remove stale socket file if it exists
        let _ = std::fs::remove_file(&path);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(&path).map_err(|e| {
            NetraError::platform(format!(
                "Failed to bind Unix Domain Socket at '{}': {}",
                path.display(),
                e
            ))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&path, permissions);
        }

        info!(socket_path = %path.display(), "Bound Unix Domain Socket IPC server");

        Ok(Self {
            socket_path: path,
            listener,
        })
    }
}

#[async_trait]
impl IpcServer for UnixDomainSocketServer {
    fn transport_name(&self) -> &'static str {
        "Unix Domain Socket"
    }

    async fn accept(
        &mut self,
    ) -> Result<(Box<dyn IpcStream + 'static>, PeerCredentials), NetraError> {
        let (stream, _addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| NetraError::platform(format!("Unix socket accept failed: {}", e)))?;

        #[cfg(target_os = "linux")]
        let (peer_pid, peer_uid) = {
            use std::os::unix::io::AsRawFd;
            let fd = stream.as_raw_fd();
            let mut ucred: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let ret = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut ucred as *mut _ as *mut _,
                    &mut len,
                )
            };
            if ret == 0 {
                let pid = ucred.pid as u32;
                let uid = ucred.uid;
                debug!(
                    pid = pid,
                    uid = uid,
                    "Retrieved SO_PEERCRED from Unix Domain Socket"
                );
                (Some(pid), Some(uid))
            } else {
                (None, None)
            }
        };

        #[cfg(not(target_os = "linux"))]
        let (peer_pid, peer_uid): (Option<u32>, Option<u32>) = (None, None);

        let framed = Framed::new(stream, IpcCodec::new());
        let credentials = PeerCredentials {
            pid: peer_pid,
            uid: peer_uid,
        };

        Ok((Box::new(framed), credentials))
    }
}

impl Drop for UnixDomainSocketServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Unix Domain Socket IPC Client.
pub struct UnixDomainSocketClient {
    socket_path: PathBuf,
}

impl UnixDomainSocketClient {
    /// Creates a new Unix Domain Socket client configured for the given path.
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }
}

#[async_trait]
impl IpcClient for UnixDomainSocketClient {
    fn transport_name(&self) -> &'static str {
        "Unix Domain Socket"
    }

    async fn connect(&self) -> Result<Box<dyn IpcStream + 'static>, NetraError> {
        let stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            NetraError::platform(format!(
                "Failed to connect to Unix socket '{}': {}",
                self.socket_path.display(),
                e
            ))
        })?;

        debug!(socket_path = %self.socket_path.display(), "Connected to Unix Domain Socket IPC server");
        let framed = Framed::new(stream, IpcCodec::new());
        Ok(Box::new(framed))
    }
}
