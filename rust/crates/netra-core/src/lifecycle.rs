use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::broadcast;
use tracing::info;

use crate::error::Result;

/// Coordinates graceful startup, execution loops, and shutdown signals.
#[derive(Debug, Clone)]
pub struct RuntimeCoordinator {
    is_running: Arc<AtomicBool>,
    shutdown_tx: broadcast::Sender<()>,
}

impl RuntimeCoordinator {
    /// Creates a new coordinator instance.
    pub fn new() -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            is_running: Arc::new(AtomicBool::new(true)),
            shutdown_tx,
        }
    }

    /// Returns whether the runtime is currently active.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    /// Subscribes to the broadcast shutdown signal channel.
    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Triggers an intentional shutdown across all active subscribers.
    pub fn trigger_shutdown(&self) {
        if self.is_running.swap(false, Ordering::SeqCst) {
            info!("RuntimeCoordinator: Initiating graceful shutdown sequence");
            let _ = self.shutdown_tx.send(());
        }
    }

    /// Waits asynchronously for an OS termination signal (Ctrl+C).
    pub async fn wait_for_signal(&self) -> Result<()> {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("OS Signal received: Ctrl+C (SIGINT)");
                self.trigger_shutdown();
            }
            _ = self.subscribe_shutdown().recv() => {
                info!("Internal shutdown signal received");
            }
        }
        Ok(())
    }
}

impl Default for RuntimeCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_runtime_coordinator_shutdown() {
        let coordinator = RuntimeCoordinator::new();
        assert!(coordinator.is_running());

        let mut rx = coordinator.subscribe_shutdown();
        coordinator.trigger_shutdown();

        assert!(!coordinator.is_running());
        assert!(rx.recv().await.is_ok());
    }
}
