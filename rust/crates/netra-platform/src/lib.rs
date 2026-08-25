//! # NETRA Platform (`netra-platform`)
//!
//! **Cross-Platform Operating System Abstraction Boundary**
//!
//! `netra-platform` provides the abstraction traits and host platform metadata discovery
//! across Windows, Linux, and macOS.
//!
//! ## Architectural Invariants & Crate Boundaries
//!
//! 1. **Dependency Direction**: `netra-platform` depends on `netra-core` for common error types
//!    and results. `netra-core` does not depend on `netra-platform`.
//! 2. **Interface Separation**: Platform-specific implementation details are confined behind the
//!    [`PlatformAdapter`] trait and native adapter stubs ([`windows::WindowsAdapter`],
//!    [`linux::LinuxAdapter`], [`macos::MacOSAdapter`]).
//! 3. **Scoped Foundation**: In Phase 2.1, this crate establishes the contract boundary only.
//!    Full native OS security capabilities (process enumeration, socket inspection, firewall COM,
//!    browser exposure) are deferred to Phase 7.
//!
//! ## Core Modules
//!
//! - [`traits`]: Cross-platform abstraction contracts ([`PlatformAdapter`], [`PlatformInfo`], [`OsFamily`]).
//! - [`info`]: Platform metadata discovery function ([`detect_platform_info`]).
//! - [`factory`]: Factory instantiation helper ([`create_platform_adapter`]).
//! - [`windows`]: Windows-specific adapter stub.
//! - [`linux`]: Linux-specific adapter stub.
//! - [`macos`]: macOS-specific adapter stub.

pub mod factory;
pub mod info;
pub mod linux;
pub mod macos;
pub mod traits;
pub mod windows;

pub use factory::create_platform_adapter;
pub use info::detect_platform_info;
pub use traits::{OsFamily, PlatformAdapter, PlatformInfo};
