//! Cross-platform Neighbor Discovery Posture Scanner adapter.

use async_trait::async_trait;
use std::time::Instant;

use netra_core::error::Result;
use netra_core::id::DeviceId;
use netra_core::observation::{
    ConfidenceScore, Observation, ObservationType, PostureScanner, PrivilegeStatus,
    SensitivityLevel, TargetDescriptor,
};

#[cfg(target_os = "linux")]
use crate::scanners::linux::neighbors::collect_linux_neighbors;
#[cfg(target_os = "macos")]
use crate::scanners::macos::neighbors::collect_macos_neighbors;
#[cfg(windows)]
use crate::scanners::windows::neighbors::collect_windows_neighbors;

use super::whoami_hostname;

/// Cross-platform Neighbor Discovery Posture Scanner.
#[derive(Debug, Default, Clone)]
pub struct PlatformNeighborScanner;

impl PlatformNeighborScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PostureScanner for PlatformNeighborScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.neighbors.v1"
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Neighbors
    }

    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        let start = Instant::now();

        #[cfg(windows)]
        let (payload, privilege_status, confidence) = (
            collect_windows_neighbors()?,
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
        );

        #[cfg(target_os = "linux")]
        let (payload, privilege_status, confidence) = (
            collect_linux_neighbors()?,
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
        );

        #[cfg(target_os = "macos")]
        let (payload, privilege_status, confidence) = (
            collect_macos_neighbors()?,
            PrivilegeStatus::Unsupported,
            ConfidenceScore::HEURISTIC,
        );

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        let (payload, privilege_status, confidence) = (
            netra_core::observation::ObservationPayload::Neighbors(
                netra_core::observation::NeighborObservationPayload::default(),
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

/// Helper function to create a new boxed `PlatformNeighborScanner`.
pub fn create_neighbor_scanner() -> Box<dyn PostureScanner> {
    Box::new(PlatformNeighborScanner::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_platform_neighbor_scanner_lifecycle() {
        let scanner = PlatformNeighborScanner::new();
        assert_eq!(scanner.scanner_id(), "scanner.neighbors.v1");
        assert_eq!(scanner.domain(), ObservationType::Neighbors);

        let device_id = DeviceId::new();
        let obs = scanner.scan(&device_id).await.unwrap();

        assert_eq!(obs.scanner_id, "scanner.neighbors.v1");
        assert_eq!(obs.observation_type, ObservationType::Neighbors);
        assert_eq!(obs.evidence_hash.len(), 64);
    }
}
