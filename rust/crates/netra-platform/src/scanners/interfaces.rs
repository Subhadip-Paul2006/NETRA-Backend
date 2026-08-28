//! Cross-platform Network Interface Posture Scanner adapter.

use async_trait::async_trait;
use std::time::Instant;

use netra_core::error::Result;
use netra_core::id::DeviceId;
use netra_core::observation::{
    ConfidenceScore, Observation, ObservationType, PostureScanner, PrivilegeStatus,
    SensitivityLevel, TargetDescriptor,
};

#[cfg(target_os = "linux")]
use crate::scanners::linux::interfaces::collect_linux_interfaces;
#[cfg(target_os = "macos")]
use crate::scanners::macos::interfaces::collect_macos_interfaces;
#[cfg(windows)]
use crate::scanners::windows::interfaces::collect_windows_interfaces;

/// Cross-platform Network Interface Posture Scanner.
#[derive(Debug, Default, Clone)]
pub struct PlatformInterfaceScanner;

impl PlatformInterfaceScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PostureScanner for PlatformInterfaceScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.interfaces.v1"
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Interfaces
    }

    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        let start = Instant::now();

        #[cfg(windows)]
        let (payload, privilege_status, confidence) = (
            collect_windows_interfaces()?,
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
        );

        #[cfg(target_os = "linux")]
        let (payload, privilege_status, confidence) = (
            collect_linux_interfaces()?,
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
        );

        #[cfg(target_os = "macos")]
        let (payload, privilege_status, confidence) = (
            collect_macos_interfaces()?,
            PrivilegeStatus::Available,
            ConfidenceScore::SYSTEM_TABLE,
        );

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        let (payload, privilege_status, confidence) = (
            netra_core::observation::ObservationPayload::Interfaces(
                netra_core::observation::InterfaceObservationPayload::default(),
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

use super::whoami_hostname;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_platform_interface_scanner_lifecycle() {
        let scanner = PlatformInterfaceScanner::new();
        assert_eq!(scanner.scanner_id(), "scanner.interfaces.v1");
        assert_eq!(scanner.domain(), ObservationType::Interfaces);

        let device_id = DeviceId::new();
        let obs = scanner.scan(&device_id).await.unwrap();

        assert_eq!(obs.schema_version, 1);
        assert_eq!(obs.device_id, device_id);
        assert_eq!(obs.observation_type, ObservationType::Interfaces);
        assert_eq!(obs.scanner_id, "scanner.interfaces.v1");

        match obs.payload {
            netra_core::observation::ObservationPayload::Interfaces(iface_payload) => {
                #[cfg(windows)]
                assert!(
                    !iface_payload.interfaces.is_empty(),
                    "Expected at least one network interface on Windows host"
                );

                for iface in &iface_payload.interfaces {
                    assert!(!iface.interface_name.is_empty());
                    if let Some(ref mac_hash) = iface.mac_address_hash {
                        assert_eq!(mac_hash.len(), 64);
                        assert!(netra_core::network::is_valid_mac_hash(mac_hash));
                    }
                }
            }
            _ => panic!("Expected Interfaces payload variant"),
        }
    }
}
