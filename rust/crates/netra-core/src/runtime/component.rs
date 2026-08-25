use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Health status classification for runtime components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComponentHealth {
    /// Component is operating normally within performance bounds.
    Healthy,

    /// Component is operating with degraded capabilities or recoverable errors.
    Degraded,

    /// Component has encountered an unrecoverable failure.
    Failed,
}

impl fmt::Display for ComponentHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComponentHealth::Healthy => write!(f, "HEALTHY"),
            ComponentHealth::Degraded => write!(f, "DEGRADED"),
            ComponentHealth::Failed => write!(f, "FAILED"),
        }
    }
}

/// Asynchronous lifecycle contract for NETRA runtime components.
///
/// Any subsystem (storage, network, scanning, telemetry, supervisor) that participates
/// in the runtime lifecycle implements this trait for coordinated startup, health monitoring,
/// and graceful reverse teardown.
#[async_trait]
pub trait ComponentLifecycle: Send + Sync {
    /// Returns a human-readable identifier for logging, telemetry, and diagnostics.
    fn name(&self) -> &'static str;

    /// Returns whether a failure during initialization or execution of this component
    /// constitutes an unrecoverable failure for the entire runtime (default: `true`).
    fn is_critical(&self) -> bool {
        true
    }

    /// Asynchronous initialization step (pre-flight checks, resource allocation, configuration).
    async fn initialize(&self) -> Result<()> {
        Ok(())
    }

    /// Starts active processing, background task loops, or schedulers.
    async fn start(&self) -> Result<()> {
        Ok(())
    }

    /// Graceful teardown step; cancels background tasks and flushes buffers.
    async fn stop(&self) -> Result<()> {
        Ok(())
    }

    /// Inquires current component health status.
    async fn health(&self) -> ComponentHealth {
        ComponentHealth::Healthy
    }
}

impl fmt::Debug for dyn ComponentLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ComponentLifecycle({})", self.name())
    }
}

/// Type alias for shared dynamic component instances.
pub type ArcComponent = Arc<dyn ComponentLifecycle>;
