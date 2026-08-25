//! # NETRA Core Runtime (`netra-core::runtime`)
//!
//! **Deterministic Runtime Lifecycle & Component Orchestration Engine**
//!
//! This module provides the central asynchronous runtime lifecycle state machine,
//! pluggable [`ComponentLifecycle`] contracts, and the [`RuntimeCoordinator`] responsible for
//! deterministic startup sequences, component health auditing, and graceful reverse teardown.

pub mod component;
pub mod coordinator;
pub mod state;

pub use component::{ArcComponent, ComponentHealth, ComponentLifecycle};
pub use coordinator::{RuntimeCoordinator, DEFAULT_SHUTDOWN_TIMEOUT_MS};
pub use state::RuntimeState;
