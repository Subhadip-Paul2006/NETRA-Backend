//! Integration tests verifying Supervisor watchdog recovery, backoff, and circuit breaker.

use netra_core::supervisor::{
    CrashAction, CrashTracker, SupervisorEngine, SupervisorState, WatchdogPolicy,
};

#[tokio::test]
async fn test_supervisor_initial_state_and_token_generation() {
    let policy = WatchdogPolicy::default();
    let supervisor = SupervisorEngine::new(policy);

    assert_eq!(supervisor.state().await, SupervisorState::Starting);

    let token = supervisor.prepare_next_worker_token().await;
    assert_eq!(token.len(), 64);
    assert_eq!(supervisor.current_token().await, Some(token));
}

#[tokio::test]
async fn test_supervisor_sub_2s_first_crash_recovery() {
    let policy = WatchdogPolicy {
        restart_delay_ms: 2000,
        ..Default::default()
    };
    let supervisor = SupervisorEngine::new(policy);

    let action = supervisor.handle_worker_exit(Some(1)).await;
    assert_eq!(action, CrashAction::Restart { delay_ms: 2000 });
    assert_eq!(supervisor.state().await, SupervisorState::Degraded);
}

#[test]
fn test_watchdog_exponential_backoff_progression() {
    let policy = WatchdogPolicy {
        restart_delay_ms: 2000,
        max_consecutive_crashes: 5,
        crash_window_secs: 300,
        ..Default::default()
    };
    let mut tracker = CrashTracker::new();

    // 1st crash -> 2000ms
    assert_eq!(
        tracker.record_crash(100, &policy),
        CrashAction::Restart { delay_ms: 2000 }
    );
    // 2nd crash -> 4000ms
    assert_eq!(
        tracker.record_crash(102, &policy),
        CrashAction::Restart { delay_ms: 4000 }
    );
    // 3rd crash -> 8000ms
    assert_eq!(
        tracker.record_crash(106, &policy),
        CrashAction::Restart { delay_ms: 8000 }
    );
    // 4th crash -> 16000ms
    assert_eq!(
        tracker.record_crash(114, &policy),
        CrashAction::Restart { delay_ms: 16000 }
    );
    // 5th crash -> Circuit Breaker
    assert_eq!(
        tracker.record_crash(130, &policy),
        CrashAction::TripCircuitBreaker { total_crashes: 5 }
    );
}

#[tokio::test]
async fn test_supervisor_graceful_shutdown() {
    let policy = WatchdogPolicy::default();
    let supervisor = SupervisorEngine::new(policy);

    supervisor.shutdown().await.expect("shutdown failed");
    assert_eq!(supervisor.state().await, SupervisorState::Stopped);
}
