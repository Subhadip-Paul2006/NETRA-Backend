//! Lifecycle states for the Tier-1 Supervisor daemon.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::{NetraError, Result};

/// Finite lifecycle states of the NETRA Tier-1 Supervisor daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupervisorState {
    /// Initial startup and IPC binding phase
    Starting,
    /// Actively monitoring worker and handling IPC
    Running,
    /// Operating with degraded worker or non-critical failure
    Degraded,
    /// Graceful teardown in progress
    Stopping,
    /// Daemon is stopped and IPC endpoint released
    Stopped,
    /// Critical unrecoverable error or circuit breaker tripped
    Failed,
}

impl SupervisorState {
    /// Validates and returns if a state transition from `self` to `target` is legal.
    pub fn can_transition_to(&self, target: SupervisorState) -> bool {
        if *self == target {
            return true;
        }

        match self {
            Self::Starting => matches!(
                target,
                Self::Running | Self::Degraded | Self::Stopping | Self::Failed
            ),
            Self::Running => matches!(target, Self::Degraded | Self::Stopping | Self::Failed),
            Self::Degraded => matches!(target, Self::Running | Self::Stopping | Self::Failed),
            Self::Stopping => matches!(target, Self::Stopped | Self::Failed),
            Self::Stopped => matches!(target, Self::Starting),
            Self::Failed => matches!(target, Self::Stopping | Self::Starting),
        }
    }

    /// Transitions to `target` state, returning an error on illegal transitions.
    pub fn transition_to(&mut self, target: SupervisorState) -> Result<()> {
        if self.can_transition_to(target) {
            *self = target;
            Ok(())
        } else {
            Err(NetraError::state_transition(*self, target))
        }
    }

    /// Returns whether the supervisor is in an active operational state.
    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Running | Self::Degraded)
    }

    /// Returns whether the supervisor has reached a terminal or stopped state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }
}

impl fmt::Display for SupervisorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Starting => "STARTING",
            Self::Running => "RUNNING",
            Self::Degraded => "DEGRADED",
            Self::Stopping => "STOPPING",
            Self::Stopped => "STOPPED",
            Self::Failed => "FAILED",
        };
        write!(f, "{}", name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_supervisor_transitions() {
        let mut state = SupervisorState::Starting;
        assert!(state.transition_to(SupervisorState::Running).is_ok());
        assert!(state.transition_to(SupervisorState::Degraded).is_ok());
        assert!(state.transition_to(SupervisorState::Running).is_ok());
        assert!(state.transition_to(SupervisorState::Stopping).is_ok());
        assert!(state.transition_to(SupervisorState::Stopped).is_ok());
    }

    #[test]
    fn test_invalid_supervisor_transitions() {
        let mut state = SupervisorState::Starting;
        assert!(state.transition_to(SupervisorState::Stopped).is_err());
    }
}
