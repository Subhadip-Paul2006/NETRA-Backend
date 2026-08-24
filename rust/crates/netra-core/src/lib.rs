//! NETRA Core Library
//!
//! Provides the fundamental abstractions, strongly-typed identifiers, structured error
//! models, configuration management, logging setup, and runtime lifecycle coordination
//! for the NETRA defensive security platform.

pub mod config;
pub mod error;
pub mod id;
pub mod lifecycle;
pub mod logging;

pub use config::{LogConfig, NetraConfig, NetworkConfig, RuntimeMode, StorageConfig};
pub use error::{ErrorKind, NetraError, Result};
pub use id::{DeviceId, FindingId, ObservationId, RemediationId, TaskId, TenantId};
pub use lifecycle::RuntimeCoordinator;
pub use logging::init_logging;
