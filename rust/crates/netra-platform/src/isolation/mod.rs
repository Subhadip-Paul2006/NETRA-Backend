#[cfg(any(
    target_os = "linux",
    not(any(target_os = "windows", target_os = "macos"))
))]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod traits;
#[cfg(target_os = "windows")]
pub mod windows;

pub use traits::ProcessIsolation;

use netra_core::error::NetraError;

/// Creates a platform-native process isolation handler for the current OS.
pub fn create_process_isolation(
    memory_limit_bytes: u64,
) -> Result<Box<dyn ProcessIsolation>, NetraError> {
    #[cfg(target_os = "windows")]
    {
        let iso = windows::WindowsJobIsolation::new(memory_limit_bytes)?;
        Ok(Box::new(iso))
    }

    #[cfg(target_os = "linux")]
    {
        let iso = linux::LinuxProcessIsolation::new(memory_limit_bytes)?;
        Ok(Box::new(iso))
    }

    #[cfg(target_os = "macos")]
    {
        let iso = macos::MacOSProcessIsolation::new(memory_limit_bytes)?;
        Ok(Box::new(iso))
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let iso = linux::LinuxProcessIsolation::new(memory_limit_bytes)?;
        Ok(Box::new(iso))
    }
}
