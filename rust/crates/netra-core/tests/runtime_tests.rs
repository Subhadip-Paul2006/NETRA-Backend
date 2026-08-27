use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use netra_core::error::{NetraError, Result};
use netra_core::runtime::{ComponentHealth, ComponentLifecycle, RuntimeCoordinator, RuntimeState};
use tokio::time::sleep;

struct TestService {
    name: &'static str,
    critical: bool,
    init_tracker: Arc<AtomicBool>,
    start_tracker: Arc<AtomicBool>,
    stop_tracker: Arc<AtomicBool>,
    order_counter: Option<Arc<AtomicUsize>>,
    stop_order_tracker: Arc<AtomicUsize>,
    fail_on_init: bool,
    fail_on_start: bool,
    fail_on_stop: bool,
    stop_delay_ms: Option<u64>,
    health_status: ComponentHealth,
}

impl TestService {
    fn new(name: &'static str, critical: bool) -> Self {
        Self {
            name,
            critical,
            init_tracker: Arc::new(AtomicBool::new(false)),
            start_tracker: Arc::new(AtomicBool::new(false)),
            stop_tracker: Arc::new(AtomicBool::new(false)),
            order_counter: None,
            stop_order_tracker: Arc::new(AtomicUsize::new(0)),
            fail_on_init: false,
            fail_on_start: false,
            fail_on_stop: false,
            stop_delay_ms: None,
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

    fn with_stop_delay(mut self, delay_ms: u64) -> Self {
        self.stop_delay_ms = Some(delay_ms);
        self
    }

    fn with_health(mut self, health: ComponentHealth) -> Self {
        self.health_status = health;
        self
    }
}

#[async_trait]
impl ComponentLifecycle for TestService {
    fn name(&self) -> &'static str {
        self.name
    }

    fn is_critical(&self) -> bool {
        self.critical
    }

    async fn initialize(&self) -> Result<()> {
        self.init_tracker.store(true, Ordering::SeqCst);
        if self.fail_on_init {
            Err(NetraError::internal("Simulated component init failure"))
        } else {
            Ok(())
        }
    }

    async fn start(&self) -> Result<()> {
        self.start_tracker.store(true, Ordering::SeqCst);
        if self.fail_on_start {
            Err(NetraError::internal("Simulated component start failure"))
        } else {
            Ok(())
        }
    }

    async fn stop(&self) -> Result<()> {
        self.stop_tracker.store(true, Ordering::SeqCst);
        if let Some(ref counter) = self.order_counter {
            let order = counter.fetch_add(1, Ordering::SeqCst);
            self.stop_order_tracker.store(order, Ordering::SeqCst);
        }

        if let Some(delay) = self.stop_delay_ms {
            sleep(Duration::from_millis(delay)).await;
        }

        if self.fail_on_stop {
            Err(NetraError::internal("Simulated component stop failure"))
        } else {
            Ok(())
        }
    }

    async fn health(&self) -> ComponentHealth {
        self.health_status
    }
}

#[tokio::test]
async fn test_runtime_complete_lifecycle() {
    let coordinator = RuntimeCoordinator::new();
    let service_a = Arc::new(TestService::new("ServiceA", true));
    let service_b = Arc::new(TestService::new("ServiceB", false));

    coordinator
        .register_component(service_a.clone())
        .await
        .unwrap();
    coordinator
        .register_component(service_b.clone())
        .await
        .unwrap();

    assert_eq!(coordinator.state().await, RuntimeState::Created);

    coordinator.initialize().await.unwrap();
    assert_eq!(coordinator.state().await, RuntimeState::Ready);
    assert!(service_a.init_tracker.load(Ordering::SeqCst));
    assert!(service_b.init_tracker.load(Ordering::SeqCst));

    coordinator.start().await.unwrap();
    assert_eq!(coordinator.state().await, RuntimeState::Running);
    assert!(service_a.start_tracker.load(Ordering::SeqCst));
    assert!(service_b.start_tracker.load(Ordering::SeqCst));

    coordinator.shutdown().await.unwrap();
    assert_eq!(coordinator.state().await, RuntimeState::Stopped);
    assert!(service_a.stop_tracker.load(Ordering::SeqCst));
    assert!(service_b.stop_tracker.load(Ordering::SeqCst));
}

#[tokio::test]
async fn test_runtime_critical_failure_triggers_failed_state() {
    let coordinator = RuntimeCoordinator::new();
    let failing_critical = Arc::new(TestService::new("CriticalService", true).with_init_failure());

    coordinator
        .register_component(failing_critical)
        .await
        .unwrap();

    let init_res = coordinator.initialize().await;
    assert!(init_res.is_err());
    assert_eq!(coordinator.state().await, RuntimeState::Failed);
}

#[tokio::test]
async fn test_runtime_non_critical_start_failure_transitions_to_degraded() {
    let coordinator = RuntimeCoordinator::new();
    let healthy_comp = Arc::new(TestService::new("HealthyService", true));
    let failing_non_critical =
        Arc::new(TestService::new("NonCriticalService", false).with_start_failure());

    coordinator.register_component(healthy_comp).await.unwrap();
    coordinator
        .register_component(failing_non_critical)
        .await
        .unwrap();

    coordinator.initialize().await.unwrap();
    assert_eq!(coordinator.state().await, RuntimeState::Ready);

    coordinator.start().await.unwrap();
    assert_eq!(coordinator.state().await, RuntimeState::Degraded);
}

#[tokio::test]
async fn test_runtime_reverse_order_teardown() {
    let counter = Arc::new(AtomicUsize::new(0));

    let coordinator = RuntimeCoordinator::new();
    let comp1 =
        Arc::new(TestService::new("FirstRegistered", true).with_order_counter(counter.clone()));
    let comp2 =
        Arc::new(TestService::new("SecondRegistered", true).with_order_counter(counter.clone()));
    let comp3 =
        Arc::new(TestService::new("ThirdRegistered", true).with_order_counter(counter.clone()));

    coordinator.register_component(comp1.clone()).await.unwrap();
    coordinator.register_component(comp2.clone()).await.unwrap();
    coordinator.register_component(comp3.clone()).await.unwrap();

    coordinator.initialize().await.unwrap();
    coordinator.start().await.unwrap();
    coordinator.shutdown().await.unwrap();

    // Reverse order: comp3 (0) -> comp2 (1) -> comp1 (2)
    assert_eq!(comp3.stop_order_tracker.load(Ordering::SeqCst), 0);
    assert_eq!(comp2.stop_order_tracker.load(Ordering::SeqCst), 1);
    assert_eq!(comp1.stop_order_tracker.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_runtime_bounded_shutdown_timeout() {
    let coordinator = RuntimeCoordinator::with_timeout(100); // 100ms grace timeout
    let slow_comp = Arc::new(TestService::new("HangingComponent", true).with_stop_delay(1000)); // 1s hang

    coordinator.register_component(slow_comp).await.unwrap();
    coordinator.initialize().await.unwrap();
    coordinator.start().await.unwrap();

    let start = std::time::Instant::now();
    coordinator.shutdown().await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(coordinator.state().await, RuntimeState::Stopped);
    assert!(
        elapsed < Duration::from_millis(2500),
        "Shutdown must not hang indefinitely"
    );
}

#[tokio::test]
async fn test_runtime_health_aggregation() {
    let coordinator = RuntimeCoordinator::new();
    let healthy = Arc::new(TestService::new("H1", true).with_health(ComponentHealth::Healthy));
    let degraded = Arc::new(TestService::new("D1", false).with_health(ComponentHealth::Degraded));

    coordinator.register_component(healthy).await.unwrap();
    coordinator.register_component(degraded).await.unwrap();

    assert_eq!(coordinator.health().await, ComponentHealth::Degraded);
}

#[tokio::test]
async fn test_runtime_timeout_continues_remaining_teardown() {
    let coordinator = RuntimeCoordinator::with_timeout(50);
    let s1 = Arc::new(TestService::new("Service1", true));
    let s2_slow = Arc::new(TestService::new("Service2Slow", true).with_stop_delay(400));
    let s3 = Arc::new(TestService::new("Service3", true));

    coordinator.register_component(s1.clone()).await.unwrap();
    coordinator.register_component(s2_slow).await.unwrap();
    coordinator.register_component(s3.clone()).await.unwrap();

    coordinator.initialize().await.unwrap();
    coordinator.start().await.unwrap();

    let res = coordinator.shutdown().await;
    assert!(res.is_ok());
    assert_eq!(coordinator.state().await, RuntimeState::Stopped);

    // Both s3 (stopped first) and s1 (stopped after slow s2) must have completed stop
    assert!(s3.stop_tracker.load(Ordering::SeqCst));
    assert!(s1.stop_tracker.load(Ordering::SeqCst));
}
