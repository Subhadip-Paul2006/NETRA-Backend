use crate::storage::error::{StorageError, StorageResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};
use uuid::Uuid;

pub const CLEAN_SHUTDOWN_FILE: &str = ".clean_shutdown";
pub const RUNTIME_ACTIVE_FILE: &str = ".runtime_active";
pub const CLEAN_SHUTDOWN_TMP: &str = ".clean_shutdown.tmp";

/// Active session metadata stored in `.runtime_active`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeActiveSession {
    pub pid: u32,
    pub session_id: String,
    pub started_at: String,
}

/// Result of acquiring a storage session.
#[derive(Debug, Clone)]
pub struct SessionAcquisition {
    pub is_unclean_restart: bool,
    pub session_id: String,
    pub previous_session: Option<RuntimeActiveSession>,
}

pub struct CleanShutdownMarker;

impl CleanShutdownMarker {
    /// Checks if a given process ID is currently running on the host OS.
    pub fn is_pid_alive(pid: u32) -> bool {
        if pid == std::process::id() {
            return true;
        }

        #[cfg(target_os = "windows")]
        {
            // Windows: OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION
            // Using powershell/tasklist check or standard Win32 handle check if available
            // Minimal fallback without direct C-FFI in core:
            let output = std::process::Command::new("cmd")
                .args(["/C", &format!("tasklist /FI \"PID eq {}\" /NH", pid)])
                .output();
            if let Ok(out) = output {
                let text = String::from_utf8_lossy(&out.stdout);
                text.contains(&pid.to_string())
            } else {
                false
            }
        }

        #[cfg(target_os = "linux")]
        {
            Path::new(&format!("/proc/{}", pid)).exists()
        }

        #[cfg(all(unix, not(target_os = "linux")))]
        {
            let output = std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .output();
            if let Ok(out) = output {
                out.status.success()
            } else {
                false
            }
        }
    }

    /// Acquires an exclusive storage session for the active process.
    ///
    /// # Safety and Invariants:
    /// - Detects if another active process is currently holding the storage directory.
    /// - Checks `.clean_shutdown` marker to determine if previous termination was unclean.
    /// - Atomically registers the current process PID in `.runtime_active`.
    pub fn acquire_session(db_dir: &Path, pid: u32) -> StorageResult<SessionAcquisition> {
        let active_path = db_dir.join(RUNTIME_ACTIVE_FILE);
        let clean_path = db_dir.join(CLEAN_SHUTDOWN_FILE);

        let mut previous_session = None;
        let mut is_unclean_restart = false;

        // 1. Inspect existing .runtime_active file
        if active_path.exists() {
            if let Ok(content) = fs::read_to_string(&active_path) {
                if let Ok(session) = serde_json::from_str::<RuntimeActiveSession>(&content) {
                    if session.pid != pid && Self::is_pid_alive(session.pid) {
                        return Err(StorageError::SessionLocked {
                            pid: session.pid,
                            path: db_dir.display().to_string(),
                        });
                    }
                    warn!(
                        previous_pid = session.pid,
                        started_at = session.started_at.as_str(),
                        "Detected stale active session from previous process run"
                    );
                    previous_session = Some(session);
                    is_unclean_restart = true;
                }
            }
        }

        // 2. Inspect .clean_shutdown file
        if !clean_path.exists() {
            is_unclean_restart = true;
        }

        // 3. Remove .clean_shutdown marker (session is now active)
        if clean_path.exists() {
            let _ = fs::remove_file(&clean_path);
        }

        // 4. Write new .runtime_active session file
        let new_session_id = Uuid::now_v7().to_string();
        let new_session = RuntimeActiveSession {
            pid,
            session_id: new_session_id.clone(),
            started_at: Utc::now().to_rfc3339(),
        };

        let session_json = serde_json::to_string_pretty(&new_session)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&active_path)
            .map_err(StorageError::Io)?;

        file.write_all(session_json.as_bytes())
            .map_err(StorageError::Io)?;
        file.flush().map_err(StorageError::Io)?;

        // Set restrictive file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&active_path, fs::Permissions::from_mode(0o600));
        }

        debug!(
            pid = pid,
            session_id = new_session_id.as_str(),
            is_unclean_restart = is_unclean_restart,
            "Storage session acquired successfully"
        );

        Ok(SessionAcquisition {
            is_unclean_restart,
            session_id: new_session_id,
            previous_session,
        })
    }

    /// Releases the storage session during graceful shutdown.
    ///
    /// # Safety and Invariants:
    /// - Only called after write completion, WAL checkpointing, and handle closure.
    /// - Removes `.runtime_active`.
    /// - Atomically writes `.clean_shutdown` via temporary file rename.
    pub fn release_session(db_dir: &Path) -> StorageResult<()> {
        let active_path = db_dir.join(RUNTIME_ACTIVE_FILE);
        let clean_path = db_dir.join(CLEAN_SHUTDOWN_FILE);
        let tmp_path = db_dir.join(CLEAN_SHUTDOWN_TMP);

        // 1. Remove .runtime_active
        if active_path.exists() {
            let _ = fs::remove_file(&active_path);
        }

        // 2. Write .clean_shutdown.tmp
        let timestamp = Utc::now().to_rfc3339();
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(StorageError::Io)?;

        file.write_all(format!("clean_shutdown_at: {timestamp}\n").as_bytes())
            .map_err(StorageError::Io)?;
        file.flush().map_err(StorageError::Io)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
        }

        // 3. Atomically rename .clean_shutdown.tmp -> .clean_shutdown
        // On Windows, if destination exists, remove first then rename
        #[cfg(windows)]
        {
            if clean_path.exists() {
                let _ = fs::remove_file(&clean_path);
            }
        }

        fs::rename(&tmp_path, &clean_path).map_err(StorageError::Io)?;

        debug!(
            shutdown_at = timestamp.as_str(),
            "Storage session released cleanly with .clean_shutdown marker"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_first_run_is_unclean_until_clean_shutdown() {
        let dir = tempdir().unwrap();
        let path = dir.path();
        let pid = std::process::id();

        // First run has no .clean_shutdown marker
        let acq1 = CleanShutdownMarker::acquire_session(path, pid).unwrap();
        assert!(acq1.is_unclean_restart);

        // Graceful release
        CleanShutdownMarker::release_session(path).unwrap();
        assert!(!path.join(RUNTIME_ACTIVE_FILE).exists());
        assert!(path.join(CLEAN_SHUTDOWN_FILE).exists());

        // Subsequent run should detect clean shutdown
        let acq2 = CleanShutdownMarker::acquire_session(path, pid).unwrap();
        assert!(!acq2.is_unclean_restart);
    }

    #[test]
    fn test_active_session_rejection_for_running_pid() {
        let dir = tempdir().unwrap();
        let path = dir.path();
        let my_pid = std::process::id();

        // Simulate another process holding active session
        let active_path = path.join(RUNTIME_ACTIVE_FILE);
        let session = RuntimeActiveSession {
            pid: my_pid, // Current process is alive
            session_id: "test-session".to_string(),
            started_at: Utc::now().to_rfc3339(),
        };
        fs::write(&active_path, serde_json::to_string(&session).unwrap()).unwrap();

        // Attempting to acquire with a different PID should fail with SessionLocked
        let other_pid = my_pid + 10000;
        // Check if my_pid is reported as alive
        if CleanShutdownMarker::is_pid_alive(my_pid) {
            let result = CleanShutdownMarker::acquire_session(path, other_pid);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("locked by active PID"));
        }
    }
}
