//! Cross-platform Routing Table & Default Gateway Posture Scanner adapter.

use async_trait::async_trait;
use std::time::Instant;

use netra_core::error::Result;
use netra_core::id::DeviceId;
use netra_core::observation::{
    ConfidenceScore, Observation, ObservationType, PostureScanner, PrivilegeStatus,
    SensitivityLevel, TargetDescriptor,
};

#[cfg(target_os = "linux")]
use crate::scanners::linux::routes::collect_linux_routes;
#[cfg(target_os = "macos")]
use crate::scanners::macos::routes::collect_macos_routes;
#[cfg(windows)]
use crate::scanners::windows::routes::collect_windows_routes;

use super::whoami_hostname;

/// Cross-platform Routing Table & Default Gateway Posture Scanner.
#[derive(Debug, Default, Clone)]
pub struct PlatformRouteScanner;

impl PlatformRouteScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PostureScanner for PlatformRouteScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.routes.v1"
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Routes
    }

    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        let start = Instant::now();

        #[cfg(windows)]
        let (payload, privilege_status, confidence) = (
            collect_windows_routes()?,
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
        );

        #[cfg(target_os = "linux")]
        let (payload, privilege_status, confidence) = (
            collect_linux_routes()?,
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
        );

        #[cfg(target_os = "macos")]
        let (payload, privilege_status, confidence) = (
            collect_macos_routes()?,
            PrivilegeStatus::Unsupported,
            ConfidenceScore::HEURISTIC,
        );

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        let (payload, privilege_status, confidence) = (
            netra_core::observation::ObservationPayload::Routes(
                netra_core::observation::RouteObservationPayload::default(),
            ),
            PrivilegeStatus::Unsupported,
            ConfidenceScore::HEURISTIC,
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
            confidence,
            SensitivityLevel::Internal,
            payload,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_platform_route_scanner_lifecycle() {
        let scanner = PlatformRouteScanner::new();
        assert_eq!(scanner.scanner_id(), "scanner.routes.v1");
        assert_eq!(scanner.domain(), ObservationType::Routes);

        let device_id = DeviceId::new();
        let obs = scanner.scan(&device_id).await.unwrap();

        assert_eq!(obs.schema_version, 1);
        assert_eq!(obs.device_id, device_id);
        assert_eq!(obs.scanner_id, "scanner.routes.v1");
        assert_eq!(obs.observation_type, ObservationType::Routes);
        assert_eq!(obs.evidence_hash.len(), 64);

        #[cfg(windows)]
        {
            assert_eq!(obs.privilege_level, PrivilegeStatus::Available);
            assert_eq!(obs.confidence, ConfidenceScore::KERNEL_AUTHORITATIVE);
            match &obs.payload {
                netra_core::observation::ObservationPayload::Routes(p) => {
                    assert!(!p.routes.is_empty(), "Windows host should have routes");
                }
                _ => panic!("Expected Routes payload variant"),
            }
        }
    }
}
