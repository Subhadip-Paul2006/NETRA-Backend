use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::{NetraError, Result};

/// Represents the deterministic lifecycle states of the NETRA runtime engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeState {
    /// Runtime coordinator allocated; no async background tasks running.
    #[default]
    Created,

    /// Configuration loaded, platform validated, and components executing initialization.
    Initializing,

    /// All registered critical components initialized and ready for execution.
    Ready,

    /// Active operational state; async schedulers, listeners, or tasks are running.
    Running,

    /// Runtime is active, but one or more non-critical components have encountered a failure.
    Degraded,

    /// Graceful teardown sequence initiated; stopping acceptance of new tasks.
    Stopping,

    /// All resources released; async tasks drained; process is ready for safe exit.
    Stopped,

    /// Critical system failure, unrecoverable initialization error, or panic caught.
    Failed,
}

impl RuntimeState {
    /// Returns whether a transition from `self` to `next` is architecturally valid.
    pub fn can_transition_to(&self, next: RuntimeState) -> bool {
        match (self, next) {
            // Self-transitions are idempotent no-ops
            (a, b) if *a == b => true,

            // Standard forward lifecycle path
            (RuntimeState::Created, RuntimeState::Initializing) => true,
            (RuntimeState::Initializing, RuntimeState::Ready) => true,
            (RuntimeState::Initializing, RuntimeState::Failed) => true,

            (RuntimeState::Ready, RuntimeState::Running) => true,
            (RuntimeState::Ready, RuntimeState::Stopping) => true,
            (RuntimeState::Ready, RuntimeState::Failed) => true,

            (RuntimeState::Running, RuntimeState::Degraded) => true,
            (RuntimeState::Running, RuntimeState::Stopping) => true,
            (RuntimeState::Running, RuntimeState::Failed) => true,

            (RuntimeState::Degraded, RuntimeState::Running) => true,
            (RuntimeState::Degraded, RuntimeState::Stopping) => true,
            (RuntimeState::Degraded, RuntimeState::Failed) => true,

            (RuntimeState::Stopping, RuntimeState::Stopped) => true,
            (RuntimeState::Stopping, RuntimeState::Failed) => true,

            // Failure handling transitions
            (RuntimeState::Failed, RuntimeState::Stopping) => true,
            (RuntimeState::Failed, RuntimeState::Stopped) => true,

            // All other transitions are illegal
            _ => false,
        }
    }

    /// Validates and enforces a state transition, returning an error if illegal.
    pub fn validate_transition(&self, next: RuntimeState) -> Result<()> {
        if self.can_transition_to(next) {
            Ok(())
        } else {
            Err(NetraError::state_transition(*self, next))
        }
    }

    /// Returns whether the runtime is in an operational processing state (`Running` or `Degraded`).
    pub fn is_operational(&self) -> bool {
        matches!(self, RuntimeState::Running | RuntimeState::Degraded)
    }

    /// Returns whether the runtime is actively alive (`Initializing`, `Ready`, `Running`, `Degraded`, `Stopping`).
    pub fn is_alive(&self) -> bool {
        !matches!(
            self,
            RuntimeState::Created | RuntimeState::Stopped | RuntimeState::Failed
        )
    }

    /// Returns whether the runtime has reached a terminal state (`Stopped` or `Failed`).
    pub fn is_terminal(&self) -> bool {
        matches!(self, RuntimeState::Stopped | RuntimeState::Failed)
    }
}

impl fmt::Display for RuntimeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeState::Created => write!(f, "CREATED"),
            RuntimeState::Initializing => write!(f, "INITIALIZING"),
            RuntimeState::Ready => write!(f, "READY"),
            RuntimeState::Running => write!(f, "RUNNING"),
            RuntimeState::Degraded => write!(f, "DEGRADED"),
            RuntimeState::Stopping => write!(f, "STOPPING"),
            RuntimeState::Stopped => write!(f, "STOPPED"),
            RuntimeState::Failed => write!(f, "FAILED"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_lifecycle_transitions() {
        // Standard operational forward path
        let mut state = RuntimeState::Created;
        assert!(state
            .validate_transition(RuntimeState::Initializing)
            .is_ok());
        state = RuntimeState::Initializing;
        assert!(state.validate_transition(RuntimeState::Ready).is_ok());
        state = RuntimeState::Ready;
        assert!(state.validate_transition(RuntimeState::Running).is_ok());
        state = RuntimeState::Running;
        assert!(state.validate_transition(RuntimeState::Degraded).is_ok());
        state = RuntimeState::Degraded;
        assert!(state.validate_transition(RuntimeState::Running).is_ok());
        state = RuntimeState::Running;
        assert!(state.validate_transition(RuntimeState::Stopping).is_ok());
        state = RuntimeState::Stopping;
        assert!(state.validate_transition(RuntimeState::Stopped).is_ok());
        state = RuntimeState::Stopped;
        assert!(state.is_terminal());

        // Degraded to Stopping
        assert!(RuntimeState::Degraded
            .validate_transition(RuntimeState::Stopping)
            .is_ok());

        // Initializing to Failed
        assert!(RuntimeState::Initializing
            .validate_transition(RuntimeState::Failed)
            .is_ok());

        // Running to Failed
        assert!(RuntimeState::Running
            .validate_transition(RuntimeState::Failed)
            .is_ok());

        // Ready to Failed
        assert!(RuntimeState::Ready
            .validate_transition(RuntimeState::Failed)
            .is_ok());

        // Failed to Stopping
        assert!(RuntimeState::Failed
            .validate_transition(RuntimeState::Stopping)
            .is_ok());

        // Failed to Stopped
        assert!(RuntimeState::Failed
            .validate_transition(RuntimeState::Stopped)
            .is_ok());

        // Ready to Stopping (direct abort before start)
        assert!(RuntimeState::Ready
            .validate_transition(RuntimeState::Stopping)
            .is_ok());
    }

    #[test]
    fn test_invalid_lifecycle_transitions() {
        // Direct jump from Created
        assert!(RuntimeState::Created
            .validate_transition(RuntimeState::Running)
            .is_err());
        assert!(RuntimeState::Created
            .validate_transition(RuntimeState::Ready)
            .is_err());
        assert!(RuntimeState::Created
            .validate_transition(RuntimeState::Degraded)
            .is_err());
        assert!(RuntimeState::Created
            .validate_transition(RuntimeState::Stopping)
            .is_err());
        assert!(RuntimeState::Created
            .validate_transition(RuntimeState::Stopped)
            .is_err());

        // Transitions from Stopped (terminal)
        assert!(RuntimeState::Stopped
            .validate_transition(RuntimeState::Running)
            .is_err());
        assert!(RuntimeState::Stopped
            .validate_transition(RuntimeState::Initializing)
            .is_err());
        assert!(RuntimeState::Stopped
            .validate_transition(RuntimeState::Stopping)
            .is_err());
        assert!(RuntimeState::Stopped
            .validate_transition(RuntimeState::Ready)
            .is_err());

        // Ready directly to Stopped (must traverse Stopping)
        assert!(RuntimeState::Ready
            .validate_transition(RuntimeState::Stopped)
            .is_err());

        // Failed to Running/Ready directly
        assert!(RuntimeState::Failed
            .validate_transition(RuntimeState::Running)
            .is_err());
        assert!(RuntimeState::Failed
            .validate_transition(RuntimeState::Ready)
            .is_err());
    }

    #[test]
    fn test_idempotent_self_transitions() {
        assert!(RuntimeState::Created
            .validate_transition(RuntimeState::Created)
            .is_ok());
        assert!(RuntimeState::Initializing
            .validate_transition(RuntimeState::Initializing)
            .is_ok());
        assert!(RuntimeState::Ready
            .validate_transition(RuntimeState::Ready)
            .is_ok());
        assert!(RuntimeState::Running
            .validate_transition(RuntimeState::Running)
            .is_ok());
        assert!(RuntimeState::Degraded
            .validate_transition(RuntimeState::Degraded)
            .is_ok());
        assert!(RuntimeState::Stopping
            .validate_transition(RuntimeState::Stopping)
            .is_ok());
        assert!(RuntimeState::Stopped
            .validate_transition(RuntimeState::Stopped)
            .is_ok());
        assert!(RuntimeState::Failed
            .validate_transition(RuntimeState::Failed)
            .is_ok());
    }

    #[test]
    fn test_state_helper_queries() {
        assert!(RuntimeState::Running.is_operational());
        assert!(RuntimeState::Degraded.is_operational());
        assert!(!RuntimeState::Ready.is_operational());
        assert!(!RuntimeState::Stopped.is_operational());

        assert!(RuntimeState::Initializing.is_alive());
        assert!(RuntimeState::Running.is_alive());
        assert!(RuntimeState::Stopping.is_alive());
        assert!(!RuntimeState::Created.is_alive());
        assert!(!RuntimeState::Stopped.is_alive());
        assert!(!RuntimeState::Failed.is_alive());

        assert!(RuntimeState::Stopped.is_terminal());
        assert!(RuntimeState::Failed.is_terminal());
        assert!(!RuntimeState::Running.is_terminal());
    }
}
