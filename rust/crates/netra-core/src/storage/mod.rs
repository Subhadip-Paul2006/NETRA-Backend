//! # NETRA Local Storage Subsystem (`netra-core::storage`)
//!
//! **Embedded SQLite WAL Engine, Schema Migrations & Local Repositories**
//!
//! Following NETRA's foundational invariant of **Local-First Determinism**, all security
//! observations, posture findings, queue buffers, and persistent configurations requiring
//! durability pass through this local storage layer before external network dispatch.

pub mod engine;
pub mod error;
pub mod marker;
pub mod migrations;
pub mod pruner;
pub mod recovery;
pub mod repositories;

pub use engine::{DatabaseEngine, StorageState, SHUTDOWN_CHECKPOINT_TIMEOUT_MS};
pub use error::{StorageError, StorageResult};
pub use marker::{
    CleanShutdownMarker, RuntimeActiveSession, SessionAcquisition, CLEAN_SHUTDOWN_FILE,
    RUNTIME_ACTIVE_FILE,
};
pub use migrations::{Migration, MigrationEngine, MIGRATIONS};
pub use pruner::{
    PruneReport, QuotaStatus, StorageQuotaManager, DEFAULT_MAX_STORAGE_BYTES, PRUNE_CRITICAL_RATIO,
    PRUNE_HIGH_WATER_RATIO, PRUNE_SATURATION_RATIO,
};
pub use recovery::{IntegrityVerification, QuarantineManager, QuarantineMetadata};
pub use repositories::{
    ConfigEntry, ConfigRepository, FindingEntry, FindingSeverity, FindingStatus,
    FindingsRepository, ObservationEntry, ObservationQueueRepository, ObservationStatus,
};
