use crate::error::{ErrorKind, NetraError};
use thiserror::Error;

/// Storage-specific error taxonomy for NETRA's embedded SQLite subsystem.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Native SQLite driver error.
    #[error("SQLite database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// Schema migration failure or tampering detected.
    #[error("Migration error: {0}")]
    Migration(String),

    /// Database corruption detected.
    #[error("Database corruption detected: {0}")]
    Corruption(String),

    /// Storage quota exceeded threshold; non-critical write rejected.
    #[error("Storage quota exceeded: current {current_bytes} bytes, limit {max_bytes} bytes")]
    QuotaExceeded { current_bytes: u64, max_bytes: u64 },

    /// Storage quota saturated; storage engine in read-only degraded mode.
    #[error("Storage quota saturated: current {current_bytes} bytes, limit {max_bytes} bytes")]
    QuotaSaturated { current_bytes: u64, max_bytes: u64 },

    /// Storage session is locked by an active process PID.
    #[error("Storage directory '{path}' is locked by active PID {pid}")]
    SessionLocked { pid: u32, path: String },

    /// Record or entity was not found in storage.
    #[error("Record not found: {0}")]
    NotFound(String),

    /// JSON serialization or deserialization failure.
    #[error("Storage serialization error: {0}")]
    Serialization(String),

    /// Filesystem I/O error during database, quarantine, or marker operations.
    #[error("Storage I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Async Tokio task join failure.
    #[error("Storage worker task failed: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),

    /// Database engine operation timed out.
    #[error("Storage operation timed out: {0}")]
    Timeout(String),

    /// Database engine is stopping or closed.
    #[error("Storage engine is stopping or closed")]
    EngineClosed,
}

impl From<StorageError> for NetraError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::Database(ref e) => {
                NetraError::new(ErrorKind::Storage, format!("Database error: {e}"))
                    .with_context("ERR_STORAGE_DATABASE")
            }
            StorageError::Migration(ref msg) => {
                NetraError::new(ErrorKind::Storage, format!("Migration error: {msg}"))
                    .with_context("ERR_STORAGE_MIGRATION")
            }
            StorageError::Corruption(ref msg) => {
                NetraError::new(ErrorKind::Storage, format!("Corruption detected: {msg}"))
                    .with_context("ERR_STORAGE_CORRUPT")
            }
            StorageError::QuotaExceeded {
                current_bytes,
                max_bytes,
            } => NetraError::new(
                ErrorKind::Storage,
                format!("Storage quota exceeded ({current_bytes}/{max_bytes} bytes)"),
            )
            .with_context("ERR_STORAGE_QUOTA_EXCEEDED"),
            StorageError::QuotaSaturated {
                current_bytes,
                max_bytes,
            } => NetraError::new(
                ErrorKind::Storage,
                format!("Storage quota saturated ({current_bytes}/{max_bytes} bytes)"),
            )
            .with_context("ERR_STORAGE_QUOTA_SATURATED"),
            StorageError::SessionLocked { pid, ref path } => NetraError::new(
                ErrorKind::Storage,
                format!("Storage directory '{path}' locked by PID {pid}"),
            )
            .with_context("ERR_STORAGE_SESSION_LOCKED"),
            StorageError::NotFound(ref msg) => {
                NetraError::new(ErrorKind::Storage, format!("Entity not found: {msg}"))
                    .with_context("ERR_STORAGE_NOT_FOUND")
            }
            StorageError::Serialization(ref msg) => {
                NetraError::new(ErrorKind::Storage, format!("Serialization error: {msg}"))
                    .with_context("ERR_STORAGE_SERIALIZATION")
            }
            StorageError::Io(ref e) => {
                NetraError::new(ErrorKind::Io, format!("Storage I/O error: {e}"))
                    .with_context("ERR_STORAGE_IO")
            }
            StorageError::TaskJoin(ref e) => NetraError::new(
                ErrorKind::Internal,
                format!("Storage worker task failed: {e}"),
            )
            .with_context("ERR_STORAGE_TASK_JOIN"),
            StorageError::Timeout(ref msg) => {
                NetraError::new(ErrorKind::Storage, format!("Storage timeout: {msg}"))
                    .with_context("ERR_STORAGE_TIMEOUT")
            }
            StorageError::EngineClosed => {
                NetraError::new(ErrorKind::Storage, "Storage engine is closed")
                    .with_context("ERR_STORAGE_ENGINE_CLOSED")
            }
        }
    }
}

pub type StorageResult<T> = std::result::Result<T, StorageError>;
