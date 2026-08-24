use std::sync::Arc;

#[cfg(target_os = "linux")]
use crate::linux::LinuxAdapter;
#[cfg(target_os = "macos")]
use crate::macos::MacOSAdapter;
use crate::traits::PlatformAdapter;
#[cfg(target_os = "windows")]
use crate::windows::WindowsAdapter;

/// Factory creating the appropriate native platform adapter for the target OS.
pub fn create_platform_adapter() -> Arc<dyn PlatformAdapter> {
    #[cfg(target_os = "windows")]
    {
        Arc::new(WindowsAdapter::new())
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(LinuxAdapter::new())
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(MacOSAdapter::new())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        // Fallback generic adapter for unsupported OS targets
        Arc::new(crate::linux::LinuxAdapter::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_platform_adapter() {
        let adapter = create_platform_adapter();
        let info = adapter.get_platform_info().await.unwrap();
        assert!(!info.hostname.is_empty());
    }
}
