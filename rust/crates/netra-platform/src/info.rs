use crate::traits::{OsFamily, PlatformInfo};

/// Detects the platform information for the current host environment.
pub fn detect_platform_info() -> PlatformInfo {
    #[cfg(target_os = "windows")]
    let os_family = OsFamily::Windows;
    #[cfg(target_os = "linux")]
    let os_family = OsFamily::Linux;
    #[cfg(target_os = "macos")]
    let os_family = OsFamily::MacOS;
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    let os_family = OsFamily::Unknown;

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
