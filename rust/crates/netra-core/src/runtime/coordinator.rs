use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, watch, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::error::{NetraError, Result};
use crate::runtime::component::{ArcComponent, ComponentHealth};
use crate::runtime::state::RuntimeState;

/// Default graceful teardown timeout ceiling per component (5 seconds).
pub const DEFAULT_SHUTDOWN_TIMEOUT_MS: u64 = 5000;

/// Central runtime coordinator managing deterministic state transitions, component lifecycles,
/// background task cancellations, and graceful teardown sequences.
#[derive(Debug, Clone)]
pub struct RuntimeCoordinator {
    state: Arc<RwLock<RuntimeState>>,
    state_tx: Arc<watch::Sender<RuntimeState>>,
    shutdown_tx: Arc<broadcast::Sender<()>>,
    components: Arc<RwLock<Vec<ArcComponent>>>,
    shutdown_timeout_ms: u64,
}

impl RuntimeCoordinator {
    /// Creates a new runtime coordinator in the initial `Created` state with default timeout.
    pub fn new() -> Self {
        Self::with_timeout(DEFAULT_SHUTDOWN_TIMEOUT_MS)
    }

    /// Creates a new runtime coordinator configured via `RuntimeConfig`.
    pub fn from_config(config: &crate::config::RuntimeConfig) -> Self {
        Self::with_timeout(config.shutdown_timeout_ms)
    }

    /// Creates a new runtime coordinator with a custom graceful shutdown timeout.
    pub fn with_timeout(shutdown_timeout_ms: u64) -> Self {
        let (state_tx, _) = watch::channel(RuntimeState::Created);
        let (shutdown_tx, _) = broadcast::channel(16);

        Self {
            state: Arc::new(RwLock::new(RuntimeState::Created)),
            state_tx: Arc::new(state_tx),
            shutdown_tx: Arc::new(shutdown_tx),
            components: Arc::new(RwLock::new(Vec::new())),
            shutdown_timeout_ms,
        }
    }

    /// Returns the configured graceful shutdown timeout in milliseconds.
    pub fn shutdown_timeout_ms(&self) -> u64 {
        self.shutdown_timeout_ms
    }

    /// Returns the current runtime lifecycle state.
    pub async fn state(&self) -> RuntimeState {
        *self.state.read().await
    }

    /// Subscribes to runtime state change notifications.
    pub fn subscribe_state(&self) -> watch::Receiver<RuntimeState> {
        self.state_tx.subscribe()
    }

    /// Subscribes to the broadcast graceful shutdown token channel.
    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Registers a component with the runtime coordinator.
    ///
    /// Components must be registered before calling `initialize()`.
    pub async fn register_component(&self, component: ArcComponent) -> Result<()> {
        let current_state = self.state().await;
        if current_state != RuntimeState::Created {
            return Err(NetraError::runtime(format!(
                "Cannot register component '{}' while runtime is in state {}",
                component.name(),
                current_state
            )));
        }

        let mut comps = self.components.write().await;
        info!("Registering runtime component: {}", component.name());
        comps.push(component);
        Ok(())
    }

    /// Transitions the runtime state if valid, notifying all subscribers.
    async fn transition_to(&self, next: RuntimeState) -> Result<()> {
        let mut state_guard = self.state.write().await;
        state_guard.validate_transition(next)?;
        let prev = *state_guard;
        *state_guard = next;
        let _ = self.state_tx.send(next);
        debug!("RuntimeState transition: {} -> {}", prev, next);
        Ok(())
    }

    /// Executes the deterministic startup initialization sequence across all registered components.
    pub async fn initialize(&self) -> Result<()> {
        self.transition_to(RuntimeState::Initializing).await?;
        info!("RuntimeCoordinator: Initializing components...");

        let comps = self.components.read().await.clone();
        for comp in comps {
            debug!("Initializing component: {}", comp.name());
            match comp.initialize().await {
                Ok(()) => {
                    debug!("Component initialized successfully: {}", comp.name());
                }
                Err(err) => {
                    if comp.is_critical() {
                        error!(
                            "Critical component '{}' initialization failed: {}",
                            comp.name(),
                            err
                        );
                        let _ = self.transition_to(RuntimeState::Failed).await;
                        return Err(NetraError::component_failure(comp.name(), err.to_string()));
                    } else {
                        warn!(
                            "Non-critical component '{}' initialization warning: {}",
                            comp.name(),
                            err
                        );
                    }
                }
            }
        }

        self.transition_to(RuntimeState::Ready).await?;
        info!("RuntimeCoordinator: Initialization complete. State is READY");
        Ok(())
    }

    /// Starts active processing across all registered components.
    pub async fn start(&self) -> Result<()> {
        let current = self.state().await;
        if current != RuntimeState::Ready {
            return Err(NetraError::runtime(format!(
                "Cannot start runtime from state {}. Expected READY",
                current
            )));
        }

        self.transition_to(RuntimeState::Running).await?;
        info!("RuntimeCoordinator: Starting active components...");

        let comps = self.components.read().await.clone();
        let mut has_degraded = false;

        for comp in comps {
            debug!("Starting component: {}", comp.name());
            match comp.start().await {
                Ok(()) => {
                    debug!("Component started: {}", comp.name());
                }
                Err(err) => {
                    if comp.is_critical() {
                        error!(
                            "Critical component '{}' failed to start: {}",
                            comp.name(),
                            err
                        );
                        let _ = self.transition_to(RuntimeState::Failed).await;
                        let _ = self.shutdown_tx.send(());
                        return Err(NetraError::component_failure(comp.name(), err.to_string()));
                    } else {
                        warn!(
                            "Non-critical component '{}' failed to start: {}",
                            comp.name(),
                            err
                        );
                        has_degraded = true;
                    }
                }
            }
        }

        if has_degraded {
            let _ = self.transition_to(RuntimeState::Degraded).await;
            warn!("RuntimeCoordinator: Runtime is operational with DEGRADED components");
        } else {
            info!("RuntimeCoordinator: All components running. State is RUNNING");
        }

        Ok(())
    }

    /// Inquires overall runtime and component health.
    pub async fn health(&self) -> ComponentHealth {
        let comps = self.components.read().await;
        let mut overall = ComponentHealth::Healthy;

        for comp in comps.iter() {
            match comp.health().await {
                ComponentHealth::Healthy => {}
                ComponentHealth::Degraded => {
                    if overall == ComponentHealth::Healthy {
                        overall = ComponentHealth::Degraded;
                    }
                }
                ComponentHealth::Failed => {
                    if comp.is_critical() {
                        return ComponentHealth::Failed;
                    }
                    overall = ComponentHealth::Degraded;
                }
            }
        }

        overall
    }

    /// Broadcasts an intentional shutdown signal across all active subscribers.
    pub async fn trigger_shutdown(&self) {
        let current = self.state().await;
        if current == RuntimeState::Stopping || current == RuntimeState::Stopped {
            return;
        }

        if current != RuntimeState::Failed {
            let _ = self.transition_to(RuntimeState::Stopping).await;
        }
        info!("RuntimeCoordinator: Initiating graceful shutdown sequence");
        let _ = self.shutdown_tx.send(());
    }

    /// Executes the reverse graceful teardown sequence across all active components.
    pub async fn shutdown(&self) -> Result<()> {
        let was_failed = self.state().await == RuntimeState::Failed;
        self.trigger_shutdown().await;

        let comps = self.components.read().await.clone();
        let timeout_duration = Duration::from_millis(self.shutdown_timeout_ms);

        // Teardown in reverse registration order
        for comp in comps.into_iter().rev() {
            debug!("Stopping component: {}", comp.name());
            match timeout(timeout_duration, comp.stop()).await {
                Ok(Ok(())) => {
                    debug!("Component stopped gracefully: {}", comp.name());
                }
                Ok(Err(err)) => {
                    warn!("Error stopping component '{}': {}", comp.name(), err);
                }
                Err(_) => {
                    warn!(
                        "Component '{}' timed out during graceful shutdown ({}ms). Forcing teardown.",
                        comp.name(),
                        self.shutdown_timeout_ms
                    );
                }
            }
        }

        if was_failed {
            info!("RuntimeCoordinator: Teardown complete. State remains FAILED");
        } else {
            self.transition_to(RuntimeState::Stopped).await?;
            info!("RuntimeCoordinator: Teardown complete. State is STOPPED");
        }

        Ok(())
    }

    /// Asynchronously waits for an OS termination signal or internal shutdown trigger.
    ///
    /// # Platform Behavior & Signal Isolation:
    /// - **Unix (Linux / macOS)**:
    ///   - Listens for `SIGINT` (Ctrl+C from terminal).
    ///   - Listens for `SIGTERM` (graceful stop request from `kill`, systemd, launchd, or container managers).
    /// - **Windows**:
    ///   - Listens for `CTRL_C_EVENT` / `CTRL_BREAK_EVENT` via Windows console handler.
    ///   - Note: Uncatchable hard kill (`TerminateProcess`) terminates immediately at the kernel level.
    ///   - Windows Service SCM control codes (`SERVICE_CONTROL_STOP`) are managed in Phase 2.3 daemon.
    /// - **Signal Isolation**:
    ///   - Signal listeners only trigger internal broadcast channels (`trigger_shutdown()`); they do not mutate state directly.
    ///   - Deterministic teardown and state mutations are strictly managed by `self.shutdown()`.
    pub async fn wait_for_shutdown(&self) -> Result<()> {
        let mut rx = self.subscribe_shutdown();

        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).map_err(|e| {
                NetraError::runtime(format!("Failed to register SIGTERM listener: {}", e))
            })?;
            let mut sigint = signal(SignalKind::interrupt()).map_err(|e| {
                NetraError::runtime(format!("Failed to register SIGINT listener: {}", e))
            })?;

            tokio::select! {
                _ = sigint.recv() => {
                    info!("OS Signal received: SIGINT (Ctrl+C)");
                    self.trigger_shutdown().await;
                }
                _ = sigterm.recv() => {
                    info!("OS Signal received: SIGTERM (Termination Request)");
                    self.trigger_shutdown().await;
                }
                _ = rx.recv() => {
                    debug!("Internal shutdown signal received");
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("OS Signal received: Ctrl+C (SIGINT)");
                    self.trigger_shutdown().await;
                }
                _ = rx.recv() => {
                    debug!("Internal shutdown signal received");
                }
            }
        }

        self.shutdown().await
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
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::time::sleep;

    struct MockComponent {
        name: &'static str,
        critical: bool,
        init_called: AtomicBool,
        start_called: AtomicBool,
        stop_called: AtomicBool,
        order_counter: Option<Arc<AtomicUsize>>,
        stop_order: Arc<AtomicUsize>,
        fail_on_init: bool,
        fail_on_start: bool,
        fail_on_stop: bool,
        slow_stop_ms: Option<u64>,
        health_status: ComponentHealth,
    }

    impl MockComponent {
        fn new(name: &'static str, critical: bool) -> Self {
            Self {
                name,
                critical,
                init_called: AtomicBool::new(false),
                start_called: AtomicBool::new(false),
                stop_called: AtomicBool::new(false),
                order_counter: None,
                stop_order: Arc::new(AtomicUsize::new(0)),
                fail_on_init: false,
                fail_on_start: false,
                fail_on_stop: false,
                slow_stop_ms: None,
                health_status: ComponentHealth::Healthy,
            }
        }

        fn with_order_counter(mut self, counter: Arc<AtomicUsize>) -> Self {
            self.order_counter = Some(counter);
            self
        }

        fn with_init_failure(mut self) -> Self {
            self.fail_on_init = true;
            self
        }

        fn with_start_failure(mut self) -> Self {
            self.fail_on_start = true;
            self
        }

        fn with_stop_failure(mut self) -> Self {
            self.fail_on_stop = true;
            self
        }

        fn with_slow_stop(mut self, delay_ms: u64) -> Self {
            self.slow_stop_ms = Some(delay_ms);
            self
        }

        fn with_health(mut self, health: ComponentHealth) -> Self {
            self.health_status = health;
            self
        }
    }

    #[async_trait]
    impl crate::runtime::component::ComponentLifecycle for MockComponent {
        fn name(&self) -> &'static str {
            self.name
        }

        fn is_critical(&self) -> bool {
            self.critical
        }

        async fn initialize(&self) -> Result<()> {
            self.init_called.store(true, Ordering::SeqCst);
            if self.fail_on_init {
                Err(NetraError::internal("Mock init failure"))
            } else {
                Ok(())
            }
        }

        async fn start(&self) -> Result<()> {
            self.start_called.store(true, Ordering::SeqCst);
            if self.fail_on_start {
                Err(NetraError::internal("Mock start failure"))
            } else {
                Ok(())
            }
        }

        async fn stop(&self) -> Result<()> {
            self.stop_called.store(true, Ordering::SeqCst);
            if let Some(ref counter) = self.order_counter {
                let order = counter.fetch_add(1, Ordering::SeqCst);
                self.stop_order.store(order, Ordering::SeqCst);
            }

            if let Some(delay) = self.slow_stop_ms {
                sleep(Duration::from_millis(delay)).await;
            }

            if self.fail_on_stop {
                Err(NetraError::internal("Mock stop failure"))
            } else {
                Ok(())
            }
        }

        async fn health(&self) -> ComponentHealth {
            self.health_status
        }
    }

    #[tokio::test]
    async fn test_full_lifecycle_success() {
        let coordinator = RuntimeCoordinator::new();
        let comp = Arc::new(MockComponent::new("mock_service", true));

        coordinator.register_component(comp.clone()).await.unwrap();
        assert_eq!(coordinator.state().await, RuntimeState::Created);

        coordinator.initialize().await.unwrap();
        assert_eq!(coordinator.state().await, RuntimeState::Ready);
        assert!(comp.init_called.load(Ordering::SeqCst));

        coordinator.start().await.unwrap();
        assert_eq!(coordinator.state().await, RuntimeState::Running);
        assert!(comp.start_called.load(Ordering::SeqCst));

        coordinator.shutdown().await.unwrap();
        assert_eq!(coordinator.state().await, RuntimeState::Stopped);
        assert!(comp.stop_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_critical_component_init_failure() {
        let coordinator = RuntimeCoordinator::new();
        let comp = Arc::new(MockComponent::new("critical_init_fail", true).with_init_failure());

        coordinator.register_component(comp).await.unwrap();
        let res = coordinator.initialize().await;
        assert!(res.is_err());
        assert_eq!(coordinator.state().await, RuntimeState::Failed);
    }

    #[tokio::test]
    async fn test_critical_component_start_failure() {
        let coordinator = RuntimeCoordinator::new();
        let comp = Arc::new(MockComponent::new("critical_start_fail", true).with_start_failure());

        coordinator.register_component(comp).await.unwrap();
        coordinator.initialize().await.unwrap();
        let res = coordinator.start().await;
        assert!(res.is_err());
        assert_eq!(coordinator.state().await, RuntimeState::Failed);
    }

    #[tokio::test]
    async fn test_non_critical_component_init_failure() {
        let coordinator = RuntimeCoordinator::new();
        let comp =
            Arc::new(MockComponent::new("non_critical_init_fail", false).with_init_failure());

        coordinator.register_component(comp).await.unwrap();
        let res = coordinator.initialize().await;
        assert!(res.is_ok());
        assert_eq!(coordinator.state().await, RuntimeState::Ready);
    }

    #[tokio::test]
    async fn test_non_critical_component_start_failure_transitions_to_degraded() {
        let coordinator = RuntimeCoordinator::new();
        let comp =
            Arc::new(MockComponent::new("non_critical_start_fail", false).with_start_failure());

        coordinator.register_component(comp).await.unwrap();
        coordinator.initialize().await.unwrap();
        coordinator.start().await.unwrap();
        assert_eq!(coordinator.state().await, RuntimeState::Degraded);
    }

    #[tokio::test]
    async fn test_reverse_teardown_order() {
        let counter = Arc::new(AtomicUsize::new(0));

        let coordinator = RuntimeCoordinator::new();
        let comp_a =
            Arc::new(MockComponent::new("comp_a", true).with_order_counter(counter.clone()));
        let comp_b =
            Arc::new(MockComponent::new("comp_b", true).with_order_counter(counter.clone()));

        // Registered in order A then B
        coordinator
            .register_component(comp_a.clone())
            .await
            .unwrap();
        coordinator
            .register_component(comp_b.clone())
            .await
            .unwrap();

        coordinator.initialize().await.unwrap();
        coordinator.start().await.unwrap();
        coordinator.shutdown().await.unwrap();

        // Stopped in reverse order: B (order 0) then A (order 1)
        assert_eq!(comp_b.stop_order.load(Ordering::SeqCst), 0);
        assert_eq!(comp_a.stop_order.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_slow_component_shutdown_timeout() {
        let coordinator = RuntimeCoordinator::with_timeout(50); // 50ms timeout
        let comp = Arc::new(MockComponent::new("slow_component", true).with_slow_stop(500)); // 500ms delay

        coordinator.register_component(comp.clone()).await.unwrap();
        coordinator.initialize().await.unwrap();
        coordinator.start().await.unwrap();

        // Shutdown should complete without blocking for 500ms
        let start = std::time::Instant::now();
        coordinator.shutdown().await.unwrap();
        let duration = start.elapsed();

        assert_eq!(coordinator.state().await, RuntimeState::Stopped);
        assert!(duration < Duration::from_millis(300));
    }

    #[tokio::test]
    async fn test_component_stop_failure_handled() {
        let coordinator = RuntimeCoordinator::new();
        let comp = Arc::new(MockComponent::new("failing_stop_comp", true).with_stop_failure());

        coordinator.register_component(comp).await.unwrap();
        coordinator.initialize().await.unwrap();
        coordinator.start().await.unwrap();

        // Shutdown should succeed even if component.stop() returns Err
        let res = coordinator.shutdown().await;
        assert!(res.is_ok());
        assert_eq!(coordinator.state().await, RuntimeState::Stopped);
    }

    #[tokio::test]
    async fn test_component_health_aggregation() {
        let coordinator = RuntimeCoordinator::new();
        let comp_healthy =
            Arc::new(MockComponent::new("c1", true).with_health(ComponentHealth::Healthy));
        let comp_degraded =
            Arc::new(MockComponent::new("c2", false).with_health(ComponentHealth::Degraded));

        coordinator.register_component(comp_healthy).await.unwrap();
        coordinator.register_component(comp_degraded).await.unwrap();

        assert_eq!(coordinator.health().await, ComponentHealth::Degraded);
    }

    #[tokio::test]
    async fn test_invalid_lifecycle_operations() {
        let coordinator = RuntimeCoordinator::new();
        coordinator.initialize().await.unwrap();

        // Registration after init must fail
        let comp = Arc::new(MockComponent::new("late_comp", true));
        assert!(coordinator.register_component(comp).await.is_err());

        // Start from Created without Init must fail on fresh coordinator
        let fresh = RuntimeCoordinator::new();
        assert!(fresh.start().await.is_err());
    }

    #[tokio::test]
    async fn test_idempotent_shutdown() {
        let coordinator = RuntimeCoordinator::new();
        coordinator.initialize().await.unwrap();
        coordinator.start().await.unwrap();

        coordinator.shutdown().await.unwrap();
        assert_eq!(coordinator.state().await, RuntimeState::Stopped);

        // Calling shutdown again should be a clean no-op
        coordinator.shutdown().await.unwrap();
        assert_eq!(coordinator.state().await, RuntimeState::Stopped);
    }

    #[tokio::test]
    async fn test_coordinator_from_config() {
        let config = crate::config::RuntimeConfig {
            shutdown_timeout_ms: 2500,
        };
        let coordinator = RuntimeCoordinator::from_config(&config);
        assert_eq!(coordinator.shutdown_timeout_ms(), 2500);
        assert_eq!(coordinator.state().await, RuntimeState::Created);
    }

    #[tokio::test]
    async fn test_component_stops_before_timeout() {
        let coordinator = RuntimeCoordinator::with_timeout(1000); // 1000ms timeout
        let comp = Arc::new(MockComponent::new("fast_comp", true)); // immediate stop

        coordinator.register_component(comp).await.unwrap();
        coordinator.initialize().await.unwrap();
        coordinator.start().await.unwrap();

        let start = std::time::Instant::now();
        let res = coordinator.shutdown().await;
        let duration = start.elapsed();

        assert!(res.is_ok());
        assert_eq!(coordinator.state().await, RuntimeState::Stopped);
        assert!(duration < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn test_component_reaches_timeout_and_remaining_shutdown_continues() {
        let coordinator = RuntimeCoordinator::with_timeout(50); // 50ms timeout per component
        let comp_fast_a = Arc::new(MockComponent::new("fast_a", true));
        let comp_slow_b = Arc::new(MockComponent::new("slow_b", true).with_slow_stop(500)); // 500ms hang
        let comp_fast_c = Arc::new(MockComponent::new("fast_c", true));

        // Registered in order A -> B -> C. Teardown will be C -> B (hangs/timeouts) -> A (must stop!)
        coordinator
            .register_component(comp_fast_a.clone())
            .await
            .unwrap();
        coordinator.register_component(comp_slow_b).await.unwrap();
        coordinator
            .register_component(comp_fast_c.clone())
            .await
            .unwrap();

        coordinator.initialize().await.unwrap();
        coordinator.start().await.unwrap();

        let res = coordinator.shutdown().await;
        assert!(res.is_ok());
        assert_eq!(coordinator.state().await, RuntimeState::Stopped);

        // Fast C and Fast A should both have their stop executed
        assert!(comp_fast_c.stop_called.load(Ordering::SeqCst));
        assert!(comp_fast_a.stop_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_timeout_reported_safely() {
        let coordinator = RuntimeCoordinator::with_timeout(30);
        let comp = Arc::new(MockComponent::new("timeout_comp", false).with_slow_stop(300));

        coordinator.register_component(comp).await.unwrap();
        coordinator.initialize().await.unwrap();
        coordinator.start().await.unwrap();

        // Shutdown reports Ok(()) safely despite internal timeout forced termination
        let res = coordinator.shutdown().await;
        assert!(res.is_ok());
        assert_eq!(coordinator.state().await, RuntimeState::Stopped);
    }

    #[tokio::test]
    async fn test_repeated_shutdown_remains_safe() {
        let coordinator = RuntimeCoordinator::new();
        coordinator.initialize().await.unwrap();
        coordinator.start().await.unwrap();

        assert!(coordinator.shutdown().await.is_ok());
        assert_eq!(coordinator.state().await, RuntimeState::Stopped);

        assert!(coordinator.shutdown().await.is_ok());
        assert_eq!(coordinator.state().await, RuntimeState::Stopped);

        assert!(coordinator.shutdown().await.is_ok());
        assert_eq!(coordinator.state().await, RuntimeState::Stopped);
    }

    #[tokio::test]
    async fn test_shutdown_broadcast_channel() {
        let coordinator = RuntimeCoordinator::new();
        let mut rx = coordinator.subscribe_shutdown();

        coordinator.trigger_shutdown().await;
        assert!(rx.recv().await.is_ok());
    }

    #[tokio::test]
    async fn test_wait_for_shutdown_internal_trigger() {
        let coordinator = RuntimeCoordinator::new();
        let comp = Arc::new(MockComponent::new("signal_comp", true));
        coordinator.register_component(comp.clone()).await.unwrap();
        coordinator.initialize().await.unwrap();
        coordinator.start().await.unwrap();

        let coord_clone = coordinator.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(20)).await;
            coord_clone.trigger_shutdown().await;
        });

        let res = coordinator.wait_for_shutdown().await;
        assert!(res.is_ok());
        assert_eq!(coordinator.state().await, RuntimeState::Stopped);
        assert!(comp.stop_called.load(Ordering::SeqCst));
    }
}
