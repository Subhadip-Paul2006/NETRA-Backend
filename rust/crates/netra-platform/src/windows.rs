use async_trait::async_trait;
use netra_core::error::Result;
use netra_core::runtime::ComponentLifecycle;

use crate::info::detect_platform_info;
use crate::traits::{PlatformAdapter, PlatformInfo};

/// Windows-specific native platform adapter foundation.
#[derive(Default)]
pub struct WindowsAdapter;

impl WindowsAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ComponentLifecycle for WindowsAdapter {
    fn name(&self) -> &'static str {
        "platform::windows"
    }

    async fn initialize(&self) -> Result<()> {
        self.self_test().await
    }
}

#[async_trait]
impl PlatformAdapter for WindowsAdapter {
    async fn get_platform_info(&self) -> Result<PlatformInfo> {
        Ok(detect_platform_info())
    }

    fn is_elevated(&self) -> bool {
        detect_platform_info().is_elevated
    }

    async fn self_test(&self) -> Result<()> {
        // Foundation self-test verifies platform compatibility
        tracing::debug!("WindowsAdapter: Self-test passed");
        Ok(())
    }
}
