use crate::config::StorageConfig;
use crate::error::{ErrorKind, NetraError};
use crate::runtime::{ComponentHealth, ComponentLifecycle};
use crate::storage::error::{StorageError, StorageResult};
use crate::storage::marker::CleanShutdownMarker;
use crate::storage::migrations::MigrationEngine;
use crate::storage::pruner::{StorageQuotaManager, DEFAULT_MAX_STORAGE_BYTES};
use crate::storage::recovery::{IntegrityVerification, QuarantineManager};
use async_trait::async_trait;
use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing::{debug, error, info, warn};

pub const SHUTDOWN_CHECKPOINT_TIMEOUT_MS: u64 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageState {
    Uninitialized,
    Ready,
    Degraded(String),
    Stopping,
    Stopped,
    Failed(String),
}

struct EngineInner {
    writer: Option<Mutex<Connection>>,
    reader: Option<Mutex<Connection>>,
    db_path: PathBuf,
    max_storage_bytes: u64,
    state: RwLock<StorageState>,
}

#[derive(Clone)]
pub struct DatabaseEngine {
    inner: Arc<EngineInner>,
}

impl DatabaseEngine {
    /// Creates a new uninitialized database engine configured for a target path.
    pub fn new(config: &StorageConfig) -> Self {
        let db_path = config.db_path.clone();
        let max_storage_bytes = if config.max_storage_bytes > 0 {
            config.max_storage_bytes
        } else {
            DEFAULT_MAX_STORAGE_BYTES
        };

        Self {
            inner: Arc::new(EngineInner {
                writer: None,
                reader: None,
                db_path,
                max_storage_bytes,
                state: RwLock::new(StorageState::Uninitialized),
            }),
        }
    }

    /// Creates an in-memory database engine for fast isolated testing.
    pub fn in_memory() -> StorageResult<Self> {
        let mut writer = Connection::open_in_memory().map_err(StorageError::Database)?;
        Self::apply_pragmas(&writer)?;
        MigrationEngine::run_pending_migrations(&mut writer)?;

        let reader = Connection::open_in_memory().map_err(StorageError::Database)?;
        Self::apply_pragmas(&reader)?;

        Ok(Self {
            inner: Arc::new(EngineInner {
                writer: Some(Mutex::new(writer)),
                reader: Some(Mutex::new(reader)),
                db_path: PathBuf::from(":memory:"),
                max_storage_bytes: DEFAULT_MAX_STORAGE_BYTES,
                state: RwLock::new(StorageState::Ready),
            }),
        })
    }

    /// Applies configured SQLite performance and durability pragmas.
    pub fn apply_pragmas(conn: &Connection) -> StorageResult<()> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;
             PRAGMA temp_store = MEMORY;
             PRAGMA cache_size = -2000;",
        )
        .map_err(StorageError::Database)?;

        Ok(())
    }

    pub fn state(&self) -> StorageState {
        self.inner.state.read().unwrap().clone()
    }

    pub fn db_path(&self) -> &Path {
        &self.inner.db_path
    }

    pub fn max_storage_bytes(&self) -> u64 {
        self.inner.max_storage_bytes
    }

    /// Dispatches a write operation onto Tokio's blocking thread pool using the exclusive writer handle.
    pub async fn with_writer<F, R>(&self, f: F) -> StorageResult<R>
    where
        F: FnOnce(&mut Connection) -> StorageResult<R> + Send + 'static,
        R: Send + 'static,
    {
        let state = self.state();
        match state {
            StorageState::Ready | StorageState::Degraded(_) => {}
            _ => return Err(StorageError::EngineClosed),
        }

        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let writer_mutex = inner
                .writer
                .as_ref()
                .ok_or(StorageError::EngineClosed)?;
            let mut conn = writer_mutex
                .lock()
                .map_err(|_| StorageError::EngineClosed)?;
            f(&mut conn)
        })
        .await
        .map_err(StorageError::TaskJoin)?
    }

    /// Dispatches a read operation onto Tokio's blocking thread pool using the shared reader handle.
    pub async fn with_reader<F, R>(&self, f: F) -> StorageResult<R>
    where
        F: FnOnce(&Connection) -> StorageResult<R> + Send + 'static,
        R: Send + 'static,
    {
        let state = self.state();
        match state {
            StorageState::Ready | StorageState::Degraded(_) => {}
            _ => return Err(StorageError::EngineClosed),
        }

        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let reader_mutex = inner
                .reader
                .as_ref()
                .ok_or(StorageError::EngineClosed)?;
            let conn = reader_mutex
                .lock()
                .map_err(|_| StorageError::EngineClosed)?;
            f(&conn)
        })
        .await
        .map_err(StorageError::TaskJoin)?
    }
}

#[async_trait]
impl ComponentLifecycle for DatabaseEngine {
    fn name(&self) -> &'static str {
        "sqlite_storage_engine"
    }

    fn is_critical(&self) -> bool {
        true
    }

    async fn initialize(&self) -> Result<(), NetraError> {
        let db_path = self.inner.db_path.clone();

        // Memory database bypasses filesystem markers
        if db_path.to_string_lossy() == ":memory:" {
            return Ok(());
        }

        let parent_dir = db_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent_dir).map_err(|e| {
            NetraError::new(ErrorKind::IoError, format!("Failed to create DB directory: {e}"))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent_dir, fs::Permissions::from_mode(0o700));
        }

        // 1. Acquire storage session & detect unclean restart
        let my_pid = std::process::id();
        let session_acq = CleanShutdownMarker::acquire_session(parent_dir, my_pid)?;

        info!(
            db_path = %db_path.display(),
            is_unclean_restart = session_acq.is_unclean_restart,
            "Opening embedded SQLite storage engine"
        );

        // 2. Open writer handle
        let mut writer = Connection::open(&db_path).map_err(|e| {
            NetraError::new(ErrorKind::StorageError, format!("Failed to open DB: {e}"))
        })?;
        Self::apply_pragmas(&writer)?;

        // 3. Tiered integrity check
        let is_corrupted = if session_acq.is_unclean_restart {
            info!("Unclean restart detected; executing Tier 2 PRAGMA quick_check");
            match IntegrityVerification::probe_tier2_quick_check(&writer) {
                Ok(dur) => {
                    debug!(duration_ms = dur.as_millis(), "Tier 2 quick_check passed cleanly");
                    false
                }
                Err(StorageError::Corruption(reason)) => {
                    error!(reason = reason.as_str(), "Database corruption detected during Tier 2 verification");
                    true
                }
                Err(e) => {
                    error!(error = %e, "Tier 2 verification query failed");
                    true
                }
            }
        } else {
            match IntegrityVerification::probe_tier1_fast(&writer) {
                Ok(dur) => {
                    debug!(duration_us = dur.as_micros(), "Tier 1 fast probe passed cleanly");
                    false
                }
                Err(_) => {
                    // Fall back to Tier 2 on probe failure
                    IntegrityVerification::probe_tier2_quick_check(&writer).is_err()
                }
            }
        };

        if is_corrupted {
            // Drop connection to release file lock
            drop(writer);

            let q_dir = QuarantineManager::execute_quarantine(&db_path, "Startup integrity check failed")?;
            warn!(
                quarantine_dir = %q_dir.display(),
                "Storage engine entering DEGRADED quarantined state"
            );

            *self.inner.state.write().unwrap() =
                StorageState::Degraded(format!("Corrupted and quarantined to {}", q_dir.display()));

            return Ok(());
        }

        // 4. Run pending schema migrations
        MigrationEngine::run_pending_migrations(&mut writer)?;

        // 5. Open reader handle
        let reader = Connection::open(&db_path).map_err(|e| {
            NetraError::new(ErrorKind::StorageError, format!("Failed to open reader handle: {e}"))
        })?;
        Self::apply_pragmas(&reader)?;

        // Unsafe cast to initialize Mutex in immutable Arc (one-time initialization)
        let inner_ptr = Arc::as_ptr(&self.inner) as *mut EngineInner;
        unsafe {
            (*inner_ptr).writer = Some(Mutex::new(writer));
            (*inner_ptr).reader = Some(Mutex::new(reader));
        }

        *self.inner.state.write().unwrap() = StorageState::Ready;
        info!("SQLite storage engine initialized and READY");

        Ok(())
    }

    async fn start(&self) -> Result<(), NetraError> {
        let state = self.state();
        match state {
            StorageState::Ready => {
                info!("Storage engine started successfully");
                Ok(())
            }
            StorageState::Degraded(ref reason) => {
                warn!(reason = reason.as_str(), "Storage engine started in DEGRADED mode");
                Ok(())
            }
            _ => Err(NetraError::new(
                ErrorKind::InternalError,
                format!("Cannot start storage engine in state {:?}", state),
            )),
        }
    }

    async fn stop(&self) -> Result<(), NetraError> {
        info!("Initiating SQLite storage engine teardown");
        *self.inner.state.write().unwrap() = StorageState::Stopping;

        let db_path = self.inner.db_path.clone();
        if db_path.to_string_lossy() == ":memory:" {
            *self.inner.state.write().unwrap() = StorageState::Stopped;
            return Ok(());
        }

        // Bounded WAL checkpoint on Tokio blocking pool with timeout
        let inner = self.inner.clone();
        let checkpoint_fut = tokio::task::spawn_blocking(move || {
            if let Some(ref writer_mutex) = inner.writer {
                if let Ok(conn) = writer_mutex.lock() {
                    let _ = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
                }
            }
        });

        let timeout_duration = Duration::from_millis(SHUTDOWN_CHECKPOINT_TIMEOUT_MS);
        if tokio::time::timeout(timeout_duration, checkpoint_fut).await.is_err() {
            warn!("Storage shutdown checkpoint timed out (1000ms); aborting checkpoint");
        }

        // Release session marker
        let parent_dir = db_path.parent().unwrap_or_else(|| Path::new("."));
        let _ = CleanShutdownMarker::release_session(parent_dir);

        *self.inner.state.write().unwrap() = StorageState::Stopped;
        info!("SQLite storage engine teardown complete. State is STOPPED");

        Ok(())
    }

    fn health(&self) -> ComponentHealth {
        match self.state() {
            StorageState::Ready => ComponentHealth::Healthy,
            StorageState::Degraded(ref reason) => ComponentHealth::Degraded(reason.clone()),
            StorageState::Failed(ref reason) => ComponentHealth::Failed(reason.clone()),
            _ => ComponentHealth::Degraded("Storage engine is not ready".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_database_engine() {
        let engine = DatabaseEngine::in_memory().unwrap();
        assert_eq!(engine.state(), StorageState::Ready);
        assert_eq!(engine.health(), ComponentHealth::Healthy);

        // Test with_writer
        let rows_inserted = engine
            .with_writer(|conn| {
                conn.execute(
                    "INSERT INTO local_config (key, value_json, value_type, updated_at) VALUES (?1, ?2, ?3, ?4)",
                    ["k1", "\"v1\"", "string", "2026-08-25T12:00:00Z"],
                )
                .map_err(StorageError::Database)
            })
            .await
            .unwrap();
        assert_eq!(rows_inserted, 1);

        // Test with_reader
        let value: String = engine
            .with_reader(|conn| {
                conn.query_row(
                    "SELECT value_json FROM local_config WHERE key = 'k1'",
                    [],
                    |row| row.get(0),
                )
                .map_err(StorageError::Database)
            })
            .await
            .unwrap();
        assert_eq!(value, "\"v1\"");
    }
}
