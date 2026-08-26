use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported transport layer socket protocols.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum SocketProtocol {
    Tcp,
    Udp,
}

impl fmt::Display for SocketProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

/// A structured record representing a single host network socket endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SocketRecord {
    pub protocol: SocketProtocol,
    pub local_address: String,
    pub local_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,
    pub state: String,
    pub owning_pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
}

/// Domain payload for socket and listening port observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SocketObservationPayload {
    pub sockets: Vec<SocketRecord>,
}

/// A structured record representing an active operating system process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessRecord {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256_binary_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub memory_rss_bytes: u64,
    pub has_command_line_args: bool,
}

/// Domain payload for process observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProcessObservationPayload {
    pub processes: Vec<ProcessRecord>,
}

/// A structured record representing a host firewall profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallProfileRecord {
    pub profile_name: String,
    pub is_enabled: bool,
    pub default_inbound_action: String,
    pub default_outbound_action: String,
    pub active_rules_count: usize,
}

/// Domain payload for host firewall observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FirewallObservationPayload {
    pub profiles: Vec<FirewallProfileRecord>,
}

/// A structured record representing a local operating system user account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRecord {
    pub username: String,
    pub uid_or_sid: String,
    pub is_enabled: bool,
    pub is_admin: bool,
    pub account_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_logon_timestamp: Option<DateTime<Utc>>,
}

/// Domain payload for user account observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UserObservationPayload {
    pub users: Vec<UserRecord>,
}

/// Operating system service runtime state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ServiceState {
    Running,
    Stopped,
    Paused,
    Unknown,
}

/// Operating system service startup configuration type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ServiceStartType {
    Auto,
    Manual,
    Disabled,
    Unknown,
}

/// A structured record representing an installed system service or background daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceRecord {
    pub service_name: String,
    pub display_name: String,
    pub state: ServiceState,
    pub start_type: ServiceStartType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_context: Option<String>,
}

/// Domain payload for system service observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ServiceObservationPayload {
    pub services: Vec<ServiceRecord>,
}

/// A structured record representing an operating system security hardening configuration check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OsConfigRecord {
    pub check_name: String,
    pub status: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Domain payload for operating system configuration observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OsConfigObservationPayload {
    pub configurations: Vec<OsConfigRecord>,
}

/// Top-level strongly typed enum wrapping all supported observation domain payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "domain", content = "data", rename_all = "snake_case")]
pub enum ObservationPayload {
    Processes(ProcessObservationPayload),
    Sockets(SocketObservationPayload),
    Firewall(FirewallObservationPayload),
    Users(UserObservationPayload),
    Services(ServiceObservationPayload),
    OsConfig(OsConfigObservationPayload),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_serialization_roundtrip() {
        let payload = ObservationPayload::Sockets(SocketObservationPayload {
            sockets: vec![SocketRecord {
                protocol: SocketProtocol::Tcp,
                local_address: "0.0.0.0".to_string(),
                local_port: 80,
                remote_address: None,
                remote_port: None,
                state: "LISTEN".to_string(),
                owning_pid: 1024,
                process_name: Some("nginx.exe".to_string()),
            }],
        });

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"domain\":\"sockets\""));
        assert!(json.contains("\"local_port\":80"));

        let deserialized: ObservationPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(payload, deserialized);
    }
}
