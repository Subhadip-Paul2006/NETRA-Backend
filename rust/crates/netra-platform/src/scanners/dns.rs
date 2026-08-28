//! Cross-platform DNS Configuration Posture Scanner adapter.

use async_trait::async_trait;
use std::time::Instant;

use netra_core::error::Result;
use netra_core::id::DeviceId;
use netra_core::observation::{
    ConfidenceScore, Observation, ObservationType, PostureScanner, PrivilegeStatus,
    SensitivityLevel, TargetDescriptor,
};

#[cfg(target_os = "linux")]
use crate::scanners::linux::dns::collect_linux_dns;
#[cfg(target_os = "macos")]
use crate::scanners::macos::dns::collect_macos_dns;
#[cfg(windows)]
use crate::scanners::windows::dns::collect_windows_dns;

use super::whoami_hostname;

/// Cross-platform DNS Configuration Posture Scanner.
#[derive(Debug, Default, Clone)]
pub struct PlatformDnsScanner;

impl PlatformDnsScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PostureScanner for PlatformDnsScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.dns.v1"
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Dns
    }

    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        let start = Instant::now();

        #[cfg(windows)]
        let (payload, privilege_status, confidence) = (
            collect_windows_dns()?,
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
        );

        #[cfg(target_os = "linux")]
        let (payload, privilege_status, confidence) = (
            collect_linux_dns()?,
            PrivilegeStatus::Available,
            ConfidenceScore::SYSTEM_TABLE,
        );

        #[cfg(target_os = "macos")]
        let (payload, privilege_status, confidence) = (
            collect_macos_dns()?,
            PrivilegeStatus::Unsupported,
            ConfidenceScore::HEURISTIC,
        );

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        let (payload, privilege_status, confidence) = (
            netra_core::observation::ObservationPayload::Dns(
                netra_core::observation::DnsObservationPayload::default(),
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
    async fn test_platform_dns_scanner_lifecycle() {
        let scanner = PlatformDnsScanner::new();
        assert_eq!(scanner.scanner_id(), "scanner.dns.v1");
        assert_eq!(scanner.domain(), ObservationType::Dns);

        let device_id = DeviceId::new();
        let obs = scanner.scan(&device_id).await.unwrap();

        assert_eq!(obs.scanner_id, "scanner.dns.v1");
        assert_eq!(obs.observation_type, ObservationType::Dns);
        assert_eq!(obs.device_id, device_id);

        #[cfg(windows)]
        {
            assert_eq!(obs.privilege_level, PrivilegeStatus::Available);
            assert_eq!(obs.confidence, ConfidenceScore::KERNEL_AUTHORITATIVE);
        }

        #[cfg(target_os = "macos")]
        {
            assert_eq!(obs.privilege_level, PrivilegeStatus::Unsupported);
            assert_eq!(obs.confidence, ConfidenceScore::HEURISTIC);
        }
    }
}
