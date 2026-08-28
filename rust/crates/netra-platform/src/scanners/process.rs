//! Cross-platform Process Posture Scanner adapter.

use async_trait::async_trait;
use std::time::Instant;

use netra_core::error::Result;
use netra_core::id::DeviceId;
use netra_core::observation::{
    ConfidenceScore, Observation, ObservationType, PostureScanner, PrivilegeStatus,
    SensitivityLevel, TargetDescriptor,
};

#[cfg(windows)]
use crate::scanners::windows::process::collect_windows_processes;

/// Cross-platform Process Posture Scanner.
#[derive(Debug, Clone, Default)]
pub struct PlatformProcessScanner {
    pub hash_binaries: bool,
}

impl PlatformProcessScanner {
    pub fn new(hash_binaries: bool) -> Self {
        Self { hash_binaries }
    }
}

#[async_trait]
impl PostureScanner for PlatformProcessScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.process.v1"
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Processes
    }

    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        let start = Instant::now();

        #[cfg(windows)]
        let (payload, privilege_status) = (
            collect_windows_processes(self.hash_binaries)?,
            PrivilegeStatus::Available,
        );

        #[cfg(not(windows))]
        let (payload, privilege_status) = (
            netra_core::observation::ObservationPayload::Processes(
                netra_core::observation::ProcessObservationPayload::default(),
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
