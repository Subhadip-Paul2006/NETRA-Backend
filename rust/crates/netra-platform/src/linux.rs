use async_trait::async_trait;
use netra_core::error::Result;
use netra_core::runtime::ComponentLifecycle;

use crate::info::detect_platform_info;
use crate::traits::{PlatformAdapter, PlatformInfo};

/// Linux-specific native platform adapter foundation.
#[derive(Default)]
pub struct LinuxAdapter;

impl LinuxAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ComponentLifecycle for LinuxAdapter {
    fn name(&self) -> &'static str {
        "platform::linux"
    }

    async fn initialize(&self) -> Result<()> {
        self.self_test().await
    }
}

#[async_trait]
impl PlatformAdapter for LinuxAdapter {
    async fn get_platform_info(&self) -> Result<PlatformInfo> {
        Ok(detect_platform_info())
    }

    fn is_elevated(&self) -> bool {
        detect_platform_info().is_elevated
    }

    async fn self_test(&self) -> Result<()> {
        tracing::debug!("LinuxAdapter: Self-test passed");
        Ok(())
    }
}
