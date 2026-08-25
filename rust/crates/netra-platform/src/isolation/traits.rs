//! Process isolation abstraction trait.

use netra_core::error::NetraError;

/// Cross-platform process isolation and resource limitation handle.
pub trait ProcessIsolation: Send + Sync {
    /// Returns the descriptive name of the isolation provider.
    fn name(&self) -> &'static str;

    /// Configures the child process command prior to spawning (e.g. setting pre-exec hooks).
    fn configure_command(&self, cmd: &mut tokio::process::Command) -> Result<(), NetraError>;

    /// Binds a newly spawned child process PID to the isolation sandbox.
    fn apply_to_pid(&self, pid: u32) -> Result<(), NetraError>;

    /// Returns the active configured memory ceiling in bytes.
    fn memory_limit_bytes(&self) -> u64;
}
