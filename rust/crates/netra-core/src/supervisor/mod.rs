//! Tier-1 Supervisor daemon models, state machine, and watchdog controller.

pub mod runner;
pub mod state;
pub mod watchdog;

pub use runner::SupervisorEngine;
pub use state::SupervisorState;
pub use watchdog::{CrashAction, CrashTracker, WatchdogPolicy};
