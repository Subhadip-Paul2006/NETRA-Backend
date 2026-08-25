//! Watchdog policy, crash tracking, exponential backoff, and circuit breaker.

use serde::{Deserialize, Serialize};

/// Policy configuration governing supervisor watchdog monitoring and crash recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchdogPolicy {
    /// Expected interval between worker telemetry heartbeats in milliseconds (default: 5000)
    pub heartbeat_interval_ms: u64,
    /// Maximum allowable elapsed time without a heartbeat before declaring worker hung (default: 15000)
    pub heartbeat_timeout_ms: u64,
    /// Initial base restart delay in milliseconds (default: 2000)
    pub restart_delay_ms: u64,
    /// Maximum consecutive crashes permitted in sliding window before tripping circuit breaker (default: 5)
    pub max_consecutive_crashes: u32,
    /// Sliding window duration in seconds for tracking crash occurrences (default: 300)
    pub crash_window_secs: u64,
    /// Duration of continuous healthy execution required to reset crash streak (default: 60)
    pub stable_reset_secs: u64,
}

impl Default for WatchdogPolicy {
    fn default() -> Self {
        Self {
            heartbeat_interval_ms: 5000,
            heartbeat_timeout_ms: 15000,
            restart_delay_ms: 2000,
            max_consecutive_crashes: 5,
            crash_window_secs: 300,
            stable_reset_secs: 60,
        }
    }
}

/// Action decision resulting from a worker crash event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrashAction {
    /// Worker should be automatically restarted after the specified delay.
    Restart { delay_ms: u64 },
    /// Circuit breaker tripped; maximum crashes exceeded. Halt automatic restarts.
    TripCircuitBreaker { total_crashes: u32 },
}

/// Dynamic crash tracker and circuit breaker state.
#[derive(Debug, Clone, Default)]
pub struct CrashTracker {
    /// Number of consecutive crashes in current window
    pub consecutive_crashes: u32,
    /// History of crash timestamps (Unix epoch seconds)
    pub crash_history: Vec<i64>,
    /// Timestamp of last received healthy heartbeat
    pub last_heartbeat_secs: Option<i64>,
    /// Timestamp when current worker instance was spawned
    pub worker_started_secs: Option<i64>,
}

impl CrashTracker {
    /// Creates a fresh crash tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a new worker launch event.
    pub fn record_worker_start(&mut self, now_secs: i64) {
        self.worker_started_secs = Some(now_secs);
        self.last_heartbeat_secs = Some(now_secs);
    }

    /// Records a successful heartbeat and resets the streak if stable threshold exceeded.
    pub fn record_heartbeat(&mut self, now_secs: i64, policy: &WatchdogPolicy) {
        self.last_heartbeat_secs = Some(now_secs);

        if let Some(started) = self.worker_started_secs {
            if now_secs.saturating_sub(started) >= policy.stable_reset_secs as i64 {
                self.consecutive_crashes = 0;
            }
        }
    }

    /// Checks if worker heartbeat has timed out based on the configured policy.
    pub fn is_heartbeat_timed_out(&self, now_secs: i64, policy: &WatchdogPolicy) -> bool {
        match self.last_heartbeat_secs {
            Some(last) => {
                let elapsed_ms = (now_secs.saturating_sub(last) as u64) * 1000;
                elapsed_ms >= policy.heartbeat_timeout_ms
            }
            None => false,
        }
    }

    /// Records a crash event and determines whether to restart with backoff or trip the circuit breaker.
    pub fn record_crash(&mut self, now_secs: i64, policy: &WatchdogPolicy) -> CrashAction {
        // Prune crashes outside sliding window
        let cutoff = now_secs.saturating_sub(policy.crash_window_secs as i64);
        self.crash_history.retain(|&ts| ts >= cutoff);

        // Record this crash
        self.crash_history.push(now_secs);
        self.consecutive_crashes += 1;
        self.last_heartbeat_secs = None;
        self.worker_started_secs = None;

        if self.consecutive_crashes >= policy.max_consecutive_crashes
            || self.crash_history.len() >= policy.max_consecutive_crashes as usize
        {
            CrashAction::TripCircuitBreaker {
                total_crashes: self.consecutive_crashes,
            }
        } else {
            // Exponential backoff: base_delay * 2^(crashes - 1), capped at 32s
            let exponent = (self.consecutive_crashes.saturating_sub(1)).min(4);
            let multiplier = 1u64 << exponent;
            let delay_ms = (policy.restart_delay_ms * multiplier).min(32000);

            CrashAction::Restart { delay_ms }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watchdog_first_crash_sub_2s_restart() {
        let policy = WatchdogPolicy::default();
        let mut tracker = CrashTracker::new();

        let action = tracker.record_crash(1000, &policy);
        assert_eq!(action, CrashAction::Restart { delay_ms: 2000 });
        assert_eq!(tracker.consecutive_crashes, 1);
    }

    #[test]
    fn test_watchdog_exponential_backoff_and_circuit_breaker() {
        let policy = WatchdogPolicy::default();
        let mut tracker = CrashTracker::new();

        // Crash 1 -> 2s
        assert_eq!(
            tracker.record_crash(1000, &policy),
            CrashAction::Restart { delay_ms: 2000 }
        );
        // Crash 2 -> 4s
        assert_eq!(
            tracker.record_crash(1002, &policy),
            CrashAction::Restart { delay_ms: 4000 }
        );
        // Crash 3 -> 8s
        assert_eq!(
            tracker.record_crash(1006, &policy),
            CrashAction::Restart { delay_ms: 8000 }
        );
        // Crash 4 -> 16s
        assert_eq!(
            tracker.record_crash(1014, &policy),
            CrashAction::Restart { delay_ms: 16000 }
        );
        // Crash 5 -> Circuit Breaker
        assert_eq!(
            tracker.record_crash(1030, &policy),
            CrashAction::TripCircuitBreaker { total_crashes: 5 }
        );
    }

    #[test]
    fn test_heartbeat_timeout_detection() {
        let policy = WatchdogPolicy::default();
        let mut tracker = CrashTracker::new();

        tracker.record_worker_start(1000);
        assert!(!tracker.is_heartbeat_timed_out(1010, &policy)); // 10s elapsed < 15s timeout
        assert!(tracker.is_heartbeat_timed_out(1016, &policy)); // 16s elapsed >= 15s timeout
    }

    #[test]
    fn test_stable_run_resets_crash_counter() {
        let policy = WatchdogPolicy::default();
        let mut tracker = CrashTracker::new();

        tracker.record_crash(1000, &policy);
        assert_eq!(tracker.consecutive_crashes, 1);

        tracker.record_worker_start(1002);
        // Heartbeat after 61 seconds of uptime
        tracker.record_heartbeat(1063, &policy);
        assert_eq!(tracker.consecutive_crashes, 0);
    }
}
