//! Cross-platform Firewall Posture Scanner adapter.

use async_trait::async_trait;
use std::time::Instant;

use netra_core::error::Result;
use netra_core::id::DeviceId;
use netra_core::observation::{
    ConfidenceScore, Observation, ObservationType, PostureScanner, PrivilegeStatus,
    SensitivityLevel, TargetDescriptor,
};

#[cfg(windows)]
use crate::scanners::windows::firewall::collect_windows_firewall;

/// Cross-platform Firewall Posture Scanner.
#[derive(Debug, Default, Clone)]
pub struct PlatformFirewallScanner;

impl PlatformFirewallScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PostureScanner for PlatformFirewallScanner {
    fn scanner_id(&self) -> &'static str {
        "scanner.firewall.v1"
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Firewall
    }

    async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
        let start = Instant::now();

        #[cfg(windows)]
        let (payload, privilege_status) = (collect_windows_firewall()?, PrivilegeStatus::Available);

        #[cfg(not(windows))]
        let (payload, privilege_status) = (
            netra_core::observation::ObservationPayload::Firewall(
                netra_core::observation::FirewallObservationPayload::default(),
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
            SensitivityLevel::Confidential,
            payload,
        )
    }
}

use super::whoami_hostname;
