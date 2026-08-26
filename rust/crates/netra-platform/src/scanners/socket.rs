//! Cross-platform Socket Posture Scanner adapter.

use async_trait::async_trait;
use std::time::Instant;

use netra_core::error::Result;
use netra_core::id::DeviceId;
use netra_core::observation::{
    ConfidenceScore, Observation, ObservationType, PostureScanner, PrivilegeStatus,
    SensitivityLevel, TargetDescriptor,
};

#[cfg(target_os = "linux")]
use crate::scanners::linux::socket::collect_linux_sockets;
#[cfg(target_os = "macos")]
use crate::scanners::macos::socket::collect_macos_sockets;
#[cfg(windows)]
use crate::scanners::windows::socket::collect_windows_sockets;

/// Cross-platform Socket Posture Scanner.
#[derive(Debug, Default, Clone)]
pub struct PlatformSocketScanner;

impl PlatformSocketScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PostureScanner for PlatformSocketScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.sockets.v1"
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Sockets
    }

    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        let start = Instant::now();

        #[cfg(windows)]
        let (payload, privilege_status) = (collect_windows_sockets()?, PrivilegeStatus::Available);

        #[cfg(target_os = "linux")]
        let (payload, privilege_status) = (collect_linux_sockets()?, PrivilegeStatus::Available);

        #[cfg(target_os = "macos")]
        let (payload, privilege_status) = (collect_macos_sockets()?, PrivilegeStatus::Available);

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        let (payload, privilege_status) = (
            netra_core::observation::ObservationPayload::Sockets(
                netra_core::observation::SocketObservationPayload::default(),
            ),
            PrivilegeStatus::Unsupported,
        );

        let duration_ms = start.elapsed().as_millis() as u64;

        Observation::new(
            device_id.clone(),
            self.scanner_id(),
            self.domain(),
            TargetDescriptor::Host {
                hostname: whoami_hostname(),
            },
            duration_ms,
            privilege_status,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            SensitivityLevel::Public,
            payload,
        )
    }
}

fn whoami_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_platform_socket_scanner_lifecycle() {
        let scanner = PlatformSocketScanner::new();
        assert_eq!(scanner.scanner_id(), "scanner.sockets.v1");
        assert_eq!(scanner.domain(), ObservationType::Sockets);

        let device_id = DeviceId::new();
        let obs = scanner.scan(&device_id).await.unwrap();

        assert_eq!(obs.schema_version, 1);
        assert_eq!(obs.device_id, device_id);
        assert_eq!(obs.observation_type, ObservationType::Sockets);
        match obs.payload {
            netra_core::observation::ObservationPayload::Sockets(sock_payload) => {
                #[cfg(windows)]
                {
                    assert!(
                        !sock_payload.sockets.is_empty(),
                        "Expected at least one socket on Windows"
                    );
                }
                let _ = sock_payload;
            }
            _ => panic!("Expected Sockets payload variant"),
        }
    }
}
