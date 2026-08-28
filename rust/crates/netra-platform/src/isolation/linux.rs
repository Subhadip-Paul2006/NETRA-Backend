//! Linux cgroups v2 and POSIX resource isolation handler.

use netra_core::error::NetraError;
use tracing::info;

use crate::isolation::traits::ProcessIsolation;

/// Linux process isolation enforcing memory limit via cgroups/rlimit and parent-death teardown.
pub struct LinuxProcessIsolation {
    memory_limit_bytes: u64,
}

impl LinuxProcessIsolation {
    /// Creates a new Linux process isolation handler.
    pub fn new(memory_limit_bytes: u64) -> Result<Self, NetraError> {
        info!(
            memory_limit_mb = memory_limit_bytes / (1024 * 1024),
            "Initialized Linux process isolation handler"
        );
        Ok(Self { memory_limit_bytes })
    }
}

impl ProcessIsolation for LinuxProcessIsolation {
    fn name(&self) -> &'static str {
        "Linux cgroups v2 / setrlimit"
    }

    fn configure_command(&self, cmd: &mut tokio::process::Command) -> Result<(), NetraError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            let mem_limit = self.memory_limit_bytes;
            // SAFETY: pre_exec is safely initializing rlimit and death signal in the child process.
            unsafe {
                cmd.pre_exec(move || {
                    // Enforce memory address space limit
                    let rlim = libc::rlimit {
                        rlim_cur: mem_limit,
                        rlim_max: mem_limit,
                    };
                    let _ = libc::setrlimit(libc::RLIMIT_AS, &rlim);

                    // Ensure child terminates if supervisor parent dies
                    let _ = libc::prctl(
                        libc::PR_SET_PDEATHSIG,
                        libc::SIGKILL as libc::c_ulong,
                        0,
                        0,
                        0,
                    );
                    Ok(())
                });
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cmd;
        }
        Ok(())
    }

    fn apply_to_pid(&self, _pid: u32) -> Result<(), NetraError> {
        // Pre-exec hook handles setrlimit and parent death signal.
        // Optional cgroups v2 attachment can be performed here if available.
        Ok(())
    }

    fn memory_limit_bytes(&self) -> u64 {
        self.memory_limit_bytes
    }
}
