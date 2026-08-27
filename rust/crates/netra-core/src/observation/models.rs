use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{NetraError, Result};
use crate::id::{DeviceId, ObservationId};
use crate::observation::payloads::ObservationPayload;
use crate::observation::target::TargetDescriptor;

/// Observation domain discriminator.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationType {
    Processes,
    Sockets,
    Firewall,
    Users,
    Services,
    OsConfig,
    Interfaces,
    Routes,
    Dns,
    Neighbors,
}

/// Execution privilege status and capability envelope for an observation collector.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrivilegeStatus {
    /// Full observation data captured with required operating system privileges.
    Available,
    /// Partial observation data captured (e.g. unprivileged standard user observing system PIDs).
    Partial,
    /// Operation denied due to insufficient operating system permissions.
    PermissionDenied,
    /// Feature or collector not supported on the target operating system.
    Unsupported,
    /// Collector encountered an internal operating error during observation.
    Error,
}

/// Explicit confidence level metric for observation data provenance.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, PartialOrd)]
pub struct ConfidenceScore(pub f64);

impl ConfidenceScore {
    /// Direct OS kernel syscall or authoritative system table (e.g. Win32 GetExtendedTcpTable, SCM).
    pub const KERNEL_AUTHORITATIVE: Self = Self(1.0);
    /// Complete process / file table query with high fidelity.
    pub const SYSTEM_TABLE: Self = Self(0.9);
    /// Unprivileged partial observation.
    pub const UNPRIVILEGED_PARTIAL: Self = Self(0.7);
    /// Fallback or heuristic measurement.
    pub const HEURISTIC: Self = Self(0.5);

    pub fn value(&self) -> f64 {
        self.0
    }
}

impl Default for ConfidenceScore {
    fn default() -> Self {
        Self::KERNEL_AUTHORITATIVE
    }
}

/// Data sensitivity classification for privacy and governance boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SensitivityLevel {
    /// Non-sensitive host telemetry (OS architecture, version, listening public port).
    Public,
    /// Internal operational metadata (service names, standard process list, user names).
    #[default]
    Internal,
    /// Sensitive host security posture (command line hashes, firewall rulesets, routing tables).
    Confidential,
    /// Highly privileged security metadata (token scopes, security descriptors).
    Restricted,
}

/// Current schema version for observation envelope.
pub const OBSERVATION_SCHEMA_VERSION: u32 = 1;

/// The canonical, normalized security observation record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Observation {
    /// Schema version for backward compatibility and migration evolution.
    pub schema_version: u32,
    /// Strongly typed UUIDv7 identifier (`obs_<hex>`).
    pub id: ObservationId,
    /// Local device identity provenance (`dev_<hex>`).
    pub device_id: DeviceId,
    /// Identifier of the collector routine (e.g. `scanner.sockets.v1`).
    pub scanner_id: String,
    /// High-level observation domain discriminator.
    pub observation_type: ObservationType,
    /// Strongly typed target descriptor.
    pub target: TargetDescriptor,
    /// UTC timestamp of observation capture.
    pub collected_at: DateTime<Utc>,
    /// Execution duration of the collector in milliseconds.
    pub duration_ms: u64,
    /// Operating system privilege level attained during collection.
    pub privilege_level: PrivilegeStatus,
    /// Telemetry confidence score.
    pub confidence: ConfidenceScore,
    /// Data sensitivity classification.
    pub sensitivity: SensitivityLevel,
    /// Strongly typed structured domain payload.
    pub payload: ObservationPayload,
    /// Cryptographic SHA-256 digest computed over canonical JSON payload.
    pub evidence_hash: String,
}

impl Observation {
    /// Constructs a new Observation, automatically computing the canonical evidence hash.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        device_id: DeviceId,
        scanner_id: impl Into<String>,
        observation_type: ObservationType,
        target: TargetDescriptor,
        duration_ms: u64,
        privilege_level: PrivilegeStatus,
        confidence: ConfidenceScore,
        sensitivity: SensitivityLevel,
        payload: ObservationPayload,
    ) -> Result<Self> {
        let evidence_hash = Self::compute_evidence_hash(&payload)?;
        Ok(Self {
            schema_version: OBSERVATION_SCHEMA_VERSION,
            id: ObservationId::new(),
            device_id,
            scanner_id: scanner_id.into(),
            observation_type,
            target,
            collected_at: Utc::now(),
            duration_ms,
            privilege_level,
            confidence,
            sensitivity,
            payload,
            evidence_hash,
        })
    }

    /// Computes the canonical SHA-256 digest of an observation payload.
    pub fn compute_evidence_hash(payload: &ObservationPayload) -> Result<String> {
        let canonical_json = serde_json::to_string(payload).map_err(|e| {
            NetraError::storage(format!("Failed to serialize canonical payload: {}", e))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(canonical_json.as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::payloads::{SocketObservationPayload, SocketProtocol, SocketRecord};

    #[test]
    fn test_observation_creation_and_evidence_hash() {
        let device_id = DeviceId::new();
        let payload = ObservationPayload::Sockets(SocketObservationPayload {
            sockets: vec![SocketRecord {
                protocol: SocketProtocol::Tcp,
                local_address: "127.0.0.1".to_string(),
                local_port: 8443,
                remote_address: None,
                remote_port: None,
                state: "LISTEN".to_string(),
                owning_pid: 4000,
                process_name: Some("netra.exe".to_string()),
            }],
        });

        let obs = Observation::new(
            device_id.clone(),
            "scanner.sockets.v1",
            ObservationType::Sockets,
            TargetDescriptor::Host {
                hostname: "localhost".to_string(),
            },
            15,
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            SensitivityLevel::Public,
            payload.clone(),
        )
        .unwrap();

        assert_eq!(obs.schema_version, 1);
        assert_eq!(obs.device_id, device_id);
        assert_eq!(obs.evidence_hash.len(), 64);
        assert_eq!(
            obs.evidence_hash,
            Observation::compute_evidence_hash(&payload).unwrap()
        );
    }
}
