//! Cross-platform OS Security Configuration Posture Scanner adapter.

use async_trait::async_trait;
use std::time::Instant;

use netra_core::error::Result;
use netra_core::id::DeviceId;
use netra_core::observation::{
    ConfidenceScore, Observation, ObservationType, PostureScanner, PrivilegeStatus,
    SensitivityLevel, TargetDescriptor,
};

#[cfg(windows)]
use crate::scanners::windows::os_config::collect_windows_os_config;

/// Cross-platform OS Security Configuration Posture Scanner.
#[derive(Debug, Default, Clone)]
pub struct PlatformOsConfigScanner;

impl PlatformOsConfigScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PostureScanner for PlatformOsConfigScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.os.v1"
    }

    fn domain(&self) -> ObservationType {
        ObservationType::OsConfig
    }

    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        let start = Instant::now();

        #[cfg(windows)]
        let (payload, privilege_status) =
            (collect_windows_os_config()?, PrivilegeStatus::Available);

        #[cfg(not(windows))]
        let (payload, privilege_status) = (
            netra_core::observation::ObservationPayload::OsConfig(
                netra_core::observation::OsConfigObservationPayload::default(),
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

fn whoami_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".to_string())
}
