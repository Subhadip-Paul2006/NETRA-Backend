use crate::traits::{OsFamily, PlatformInfo};

/// Detects the platform information for the current host environment.
pub fn detect_platform_info() -> PlatformInfo {
    let os_family = if cfg!(target_os = "windows") {
        OsFamily::Windows
    } else if cfg!(target_os = "linux") {
        OsFamily::Linux
    } else if cfg!(target_os = "macos") {
        OsFamily::MacOS
    } else {
        OsFamily::Unknown
    };

    let arch = std::env::consts::ARCH.to_string();

    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".to_string());

    let os_version = std::env::consts::OS.to_string();

    let is_elevated = check_elevation();

    PlatformInfo {
        os_family,
        os_version,
        arch,
        hostname,
        is_elevated,
    }
}

/// Helper to check privilege elevation status (foundation implementation).
fn check_elevation() -> bool {
    #[cfg(target_os = "windows")]
    {
        false
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_platform_info() {
        let info = detect_platform_info();
        assert_ne!(info.os_family, OsFamily::Unknown);
        assert!(!info.arch.is_empty());
        assert!(!info.hostname.is_empty());
    }
}
