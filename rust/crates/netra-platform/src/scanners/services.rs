//! Cross-platform Service Posture Scanner adapter.

use async_trait::async_trait;
use std::time::Instant;

use netra_core::error::Result;
use netra_core::id::DeviceId;
use netra_core::observation::{
    ConfidenceScore, Observation, ObservationType, PostureScanner, PrivilegeStatus,
    SensitivityLevel, TargetDescriptor,
};

#[cfg(windows)]
use crate::scanners::windows::services::collect_windows_services;

/// Cross-platform Service Posture Scanner.
#[derive(Debug, Default, Clone)]
pub struct PlatformServiceScanner;

impl PlatformServiceScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PostureScanner for PlatformServiceScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.services.v1"
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Services
    }

    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        let start = Instant::now();

        #[cfg(windows)]
        let (payload, privilege_status) = (collect_windows_services()?, PrivilegeStatus::Available);

        #[cfg(not(windows))]
        let (payload, privilege_status) = (
            netra_core::observation::ObservationPayload::Services(
                netra_core::observation::ServiceObservationPayload::default(),
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
            SensitivityLevel::Internal,
            payload,
        )
    }
}

use super::whoami_hostname;
