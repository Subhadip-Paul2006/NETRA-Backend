//! # NETRA Core (`netra-core`)
//!
//! **Domain-Neutral Runtime Foundation for NETRA**
//!
//! `netra-core` serves as the root foundational crate of the NETRA defensive security
//! framework. It establishes foundational types, strongly-typed UUIDv7 identifiers,
//! a structured error taxonomy, configuration schemas, structured logging initialization,
//! and asynchronous lifecycle coordination.
//!
//! ## Architectural Invariants & Crate Boundaries
//!
//! 1. **Zero Internal Workspace Dependencies**: `netra-core` has zero dependencies on other
//!    crates in the workspace (neither `netra-platform` nor `netra-cli`).
//! 2. **Domain Neutrality**: `netra-core` contains no presentation logic, no operating system
//!    syscalls, no network transport implementations, and no database engine drivers.
//! 3. **No Speculative Abstractions**: Complex scanner registries and SQLite persistence models
//!    are deferred to their respective feature phases (Phase 7 and Phase 3).
//!
//! ## Core Modules
//!
//! - [`config`]: Strongly-typed configuration schemas, TOML loading, and environment variable overrides.
//! - [`error`]: Unified [`NetraError`] structure with categorized [`ErrorKind`] and machine codes.
//! - [`id`]: Strongly-typed prefixed UUIDv7 identifiers ([`DeviceId`], [`TenantId`], [`TaskId`], [`FindingId`], [`ObservationId`], [`RemediationId`]).
//! - [`ipc`]: Local IPC protocol schemas, length-delimited codec, and token authentication.
//! - [`lifecycle`]: Asynchronous [`RuntimeCoordinator`] and lifecycle compatibility layer.
//! - [`logging`]: Structured subscriber initialization supporting human ANSI and machine JSON formats.
//! - [`runtime`]: Complete runtime state machine ([`RuntimeState`]), coordinator ([`RuntimeCoordinator`]), and component contracts ([`ComponentLifecycle`]).
//! - [`supervisor`]: Tier-1 Supervisor daemon state machine, watchdog policies, and crash trackers.
//! - [`worker`]: Tier-2 Worker process runtime harness and IPC client integration.

pub mod config;
pub mod error;
pub mod id;
pub mod identity;
pub mod ipc;
pub mod keystore;
pub mod lifecycle;
pub mod logging;
pub mod runtime;
pub mod storage;
pub mod supervisor;
pub mod worker;

pub use config::{
    LogConfig, NetraConfig, NetworkConfig, RuntimeConfig, RuntimeMode, StorageConfig,
};
pub use error::{ErrorKind, NetraError, Result};
pub use id::{DeviceId, FindingId, ObservationId, RemediationId, TaskId, TenantId};
pub use ipc::{
    generate_ipc_token, verify_ipc_token, IpcCodec, IpcEnvelope, IpcPayload, IPC_PROTOCOL_VERSION,
    MAX_IPC_FRAME_SIZE,
};
pub use logging::init_logging;
pub use runtime::{
    ArcComponent, ComponentHealth, ComponentLifecycle, RuntimeCoordinator, RuntimeState,
    DEFAULT_SHUTDOWN_TIMEOUT_MS,
};
pub use storage::{
    ConfigEntry, ConfigRepository, DatabaseEngine, FindingEntry, FindingSeverity, FindingStatus,
    FindingsRepository, MigrationEngine, ObservationEntry, ObservationQueueRepository,
    ObservationStatus, StorageError, StorageQuotaManager, StorageResult, StorageState,
};
pub use supervisor::{
    CrashAction, CrashTracker, SupervisorEngine, SupervisorState, WatchdogPolicy,
};
pub use worker::WorkerHarness;
