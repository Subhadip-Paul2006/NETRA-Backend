//! macOS POSIX resource isolation handler.

use netra_core::error::NetraError;
use tracing::info;

use crate::isolation::traits::ProcessIsolation;

/// macOS process isolation enforcing memory limits via setrlimit.
pub struct MacOSProcessIsolation {
    memory_limit_bytes: u64,
}

impl MacOSProcessIsolation {
    /// Creates a new macOS process isolation handler.
    pub fn new(memory_limit_bytes: u64) -> Result<Self, NetraError> {
        info!(
            memory_limit_mb = memory_limit_bytes / (1024 * 1024),
            "Initialized macOS process isolation handler"
        );
        Ok(Self { memory_limit_bytes })
    }
}

impl ProcessIsolation for MacOSProcessIsolation {
    fn name(&self) -> &'static str {
        "macOS POSIX setrlimit"
    }

    fn configure_command(&self, _cmd: &mut tokio::process::Command) -> Result<(), NetraError> {
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::process::CommandExt;
            let mem_limit = self.memory_limit_bytes;
            unsafe {
                _cmd.pre_exec(move || {
                    let rlim = libc::rlimit {
                        rlim_cur: mem_limit,
                        rlim_max: mem_limit,
                    };
                    libc::setrlimit(libc::RLIMIT_AS, &rlim);
                    Ok(())
                });
            }
        }
        Ok(())
    }

    fn apply_to_pid(&self, _pid: u32) -> Result<(), NetraError> {
        Ok(())
    }

    fn memory_limit_bytes(&self) -> u64 {
        self.memory_limit_bytes
    }
}
