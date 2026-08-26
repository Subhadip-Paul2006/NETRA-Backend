use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

use netra_core::runtime::RuntimeCoordinator;
use netra_core::storage::DatabaseEngine;

use crate::config::ApiConfig;

/// Shared application state across all Axum route handlers.
#[derive(Clone)]
pub struct AppState {
    /// Runtime coordinator managing subsystem states.
    pub coordinator: Arc<RuntimeCoordinator>,
    /// SQLite database engine reference (if storage is active).
    pub storage: Option<Arc<DatabaseEngine>>,
    /// In-memory single-flight lock preventing concurrent deep integrity checks.
    pub deep_check_lock: Arc<AtomicBool>,
    /// Gateway configuration settings.
    pub config: Arc<ApiConfig>,
    /// Service startup instant for tracking uptime.
    pub start_time: Instant,
}

impl AppState {
    /// Creates a new AppState instance.
    pub fn new(
        coordinator: Arc<RuntimeCoordinator>,
        storage: Option<Arc<DatabaseEngine>>,
        config: ApiConfig,
    ) -> Self {
        Self {
            coordinator,
            storage,
            deep_check_lock: Arc::new(AtomicBool::new(false)),
            config: Arc::new(config),
            start_time: Instant::now(),
        }
    }

    /// Returns elapsed uptime in seconds.
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}
