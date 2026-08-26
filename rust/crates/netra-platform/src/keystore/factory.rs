use std::path::PathBuf;
use std::sync::Arc;

#[allow(unused_imports)]
use netra_core::error::{NetraError, Result};
use netra_core::keystore::KeyStore;

#[cfg(target_os = "linux")]
use crate::keystore::linux::LinuxSecretServiceKeystore;
#[cfg(target_os = "macos")]
use crate::keystore::macos::MacosKeychainKeystore;
#[cfg(windows)]
use crate::keystore::windows::WindowsDpapiKeystore;

#[cfg(feature = "insecure-dev-keystore")]
use crate::keystore::dev_insecure::InsecureDevKeystore;

/// Creates the native OS-protected KeyStore instance for the current platform.
pub fn create_platform_keystore(custom_dir: Option<PathBuf>) -> Result<Arc<dyn KeyStore>> {
    #[cfg(windows)]
    {
        let base_dir = custom_dir.unwrap_or_else(|| {
            let local_app_data =
                std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:\\ProgramData".to_string());
            PathBuf::from(local_app_data).join("NETRA").join("keystore")
        });
        let keystore = WindowsDpapiKeystore::new(base_dir)?;
        Ok(Arc::new(keystore))
    }

    #[cfg(target_os = "macos")]
    {
        let _ = custom_dir;
        Ok(Arc::new(MacosKeychainKeystore::new()))
    }

    #[cfg(target_os = "linux")]
    {
        let _ = custom_dir;
        Ok(Arc::new(LinuxSecretServiceKeystore::new()))
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = custom_dir;
        Err(NetraError::platform("Unsupported platform for OS KeyStore"))
    }
}

/// Creates an insecure development KeyStore (ONLY available when feature `insecure-dev-keystore` is active).
#[cfg(feature = "insecure-dev-keystore")]
pub fn create_insecure_dev_keystore(dir: PathBuf) -> Result<Arc<dyn KeyStore>> {
    let keystore = InsecureDevKeystore::new(dir)?;
    Ok(Arc::new(keystore))
}
