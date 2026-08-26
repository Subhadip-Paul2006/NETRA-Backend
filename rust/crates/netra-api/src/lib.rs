pub mod config;
pub mod errors;
pub mod middleware;
pub mod openapi;
pub mod routes;
pub mod state;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::middleware as axum_mw;
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tower_http::trace::TraceLayer;

use netra_core::error::{NetraError, Result};
use netra_core::runtime::{ComponentHealth, ComponentLifecycle, RuntimeCoordinator};
use netra_core::storage::DatabaseEngine;

pub use config::ApiConfig;
pub use errors::{ApiError, ErrorDetail, ErrorEnvelope, MetaEnvelope, SuccessEnvelope};
pub use openapi::ApiDoc;
pub use state::AppState;

/// Asynchronous REST API Gateway service implementing `ComponentLifecycle`.
pub struct ApiService {
    config: ApiConfig,
    state: AppState,
    listener: Mutex<Option<TcpListener>>,
    shutdown_tx: Mutex<Option<watch::Sender<bool>>>,
    server_handle: Mutex<Option<JoinHandle<()>>>,
    is_running: AtomicBool,
}

impl ApiService {
    /// Creates a new ApiService instance.
    pub fn new(
        config: ApiConfig,
        coordinator: Arc<RuntimeCoordinator>,
        storage: Option<Arc<DatabaseEngine>>,
    ) -> Self {
        let state = AppState::new(coordinator, storage, config.clone());
        Self {
            config,
            state,
            listener: Mutex::new(None),
            shutdown_tx: Mutex::new(None),
            server_handle: Mutex::new(None),
            is_running: AtomicBool::new(false),
        }
    }

    /// Returns the underlying AppState.
    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Builds the complete Axum router with all middleware layers attached.
    pub fn build_router(state: AppState) -> Router {
        let max_body_bytes = state.config.max_body_bytes;

        routes::create_router(state)
            .layer(axum::extract::DefaultBodyLimit::max(max_body_bytes))
            .layer(axum_mw::from_fn(middleware::no_cache_middleware))
            .layer(axum_mw::from_fn(middleware::request_id_middleware))
            .layer(TraceLayer::new_for_http())
    }
}

#[async_trait]
impl ComponentLifecycle for ApiService {
    fn name(&self) -> &'static str {
        "rest_api_gateway"
    }

    async fn initialize(&self) -> Result<()> {
        // Validate config enforcing strict loopback binding
        if let Err(e) = self.config.validate() {
            return Err(NetraError::config(format!(
                "API configuration error: {}",
                e
            )));
        }

        let bind_addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = TcpListener::bind(&bind_addr).await.map_err(|e| {
            NetraError::runtime(format!(
                "Failed to bind REST API listener to '{}' (ERR_PORT_IN_USE): {}",
                bind_addr, e
            ))
        })?;

        tracing::info!(bind_addr = %bind_addr, "REST API Gateway TCP listener bound successfully");
        *self.listener.lock().await = Some(listener);
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        let listener =
            self.listener.lock().await.take().ok_or_else(|| {
                NetraError::runtime("REST API listener not initialized".to_string())
            })?;

        let router = Self::build_router(self.state.clone());
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        *self.shutdown_tx.lock().await = Some(shutdown_tx);

        let handle = tokio::spawn(async move {
            let server = axum::serve(listener, router).with_graceful_shutdown(async move {
                let _ = shutdown_rx.wait_for(|&is_shutdown| is_shutdown).await;
            });

            if let Err(err) = server.await {
                tracing::error!(error = %err, "REST API Gateway server error encountered");
            }
        });

        *self.server_handle.lock().await = Some(handle);
        self.is_running.store(true, Ordering::SeqCst);
        tracing::info!(host = %self.config.host, port = self.config.port, "REST API Gateway server started");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        tracing::info!("Stopping REST API Gateway and draining in-flight requests");

        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(true);
        }

        if let Some(handle) = self.server_handle.lock().await.take() {
            // Wait for graceful shutdown of Axum server bounded by budget
            let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;
        }

        self.is_running.store(false, Ordering::SeqCst);
        tracing::info!("REST API Gateway stopped cleanly");
        Ok(())
    }

    async fn health(&self) -> ComponentHealth {
        if self.is_running.load(Ordering::SeqCst) {
            ComponentHealth::Healthy
        } else {
            ComponentHealth::Degraded
        }
    }
}
