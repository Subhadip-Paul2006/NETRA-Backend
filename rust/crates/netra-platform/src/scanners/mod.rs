//! # Host Posture Scanners
//!
//! Native operating system collectors for security posture telemetry.

pub mod firewall;
pub mod interfaces;
#[allow(dead_code, unused_imports)]
pub mod linux;
#[allow(dead_code, unused_imports)]
pub mod macos;
pub mod os_config;
pub mod process;
pub mod services;
pub mod socket;
pub mod users;
#[allow(dead_code, unused_imports)]
pub mod windows;

pub use firewall::PlatformFirewallScanner;
pub use interfaces::PlatformInterfaceScanner;
pub use os_config::PlatformOsConfigScanner;
pub use process::PlatformProcessScanner;
pub use services::PlatformServiceScanner;
pub use socket::PlatformSocketScanner;
pub use users::PlatformUserScanner;

use netra_core::observation::PostureScanner;
use std::sync::Arc;

/// Creates the native OS Socket Posture Scanner.
pub fn create_socket_scanner() -> Arc<dyn PostureScanner> {
    Arc::new(PlatformSocketScanner::new())
}

/// Creates the native OS Network Interface Posture Scanner.
pub fn create_interface_scanner() -> Arc<dyn PostureScanner> {
    Arc::new(PlatformInterfaceScanner::new())
}

/// Creates all native OS Posture Scanners for the host.
pub fn create_all_platform_scanners(hash_binaries: bool) -> Vec<Arc<dyn PostureScanner>> {
    vec![
        Arc::new(PlatformSocketScanner::new()),
        Arc::new(PlatformProcessScanner::new(hash_binaries)),
        Arc::new(PlatformFirewallScanner::new()),
        Arc::new(PlatformUserScanner::new()),
        Arc::new(PlatformServiceScanner::new()),
        Arc::new(PlatformOsConfigScanner::new()),
        Arc::new(PlatformInterfaceScanner::new()),
    ]
}
