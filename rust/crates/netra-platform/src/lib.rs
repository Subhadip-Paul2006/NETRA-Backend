//! NETRA Platform Library
//!
//! Provides the cross-platform abstraction traits and host platform metadata discovery
//! across Windows, Linux, and macOS.

pub mod factory;
pub mod info;
pub mod linux;
pub mod macos;
pub mod traits;
pub mod windows;

pub use factory::create_platform_adapter;
pub use info::detect_platform_info;
pub use traits::{OsFamily, PlatformAdapter, PlatformInfo};
