//! # Security Observation & Telemetry Models
//!
//! Strongly typed observation models, structured domain payloads, target descriptors,
//! deterministic evidence hashing, and scanner contracts.

pub mod models;
pub mod payloads;
pub mod supervisor;
pub mod target;
pub mod traits;

pub use models::{
    ConfidenceScore, Observation, ObservationType, PrivilegeStatus, SensitivityLevel,
    OBSERVATION_SCHEMA_VERSION,
};
pub use payloads::{
    FirewallObservationPayload, FirewallProfileRecord, ObservationPayload,
    OsConfigObservationPayload, OsConfigRecord, ProcessObservationPayload, ProcessRecord,
    ServiceObservationPayload, ServiceRecord, ServiceStartType, ServiceState,
    SocketObservationPayload, SocketProtocol, SocketRecord, UserObservationPayload, UserRecord,
};
pub use supervisor::{ScanCycleResult, ScannerSupervisor, SCANNER_TIMEOUT_MS};
pub use target::TargetDescriptor;
pub use traits::PostureScanner;
