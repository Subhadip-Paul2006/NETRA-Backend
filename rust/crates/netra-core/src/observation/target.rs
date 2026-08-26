use serde::{Deserialize, Serialize};

use crate::observation::payloads::SocketProtocol;

/// Strongly typed target descriptor identifying the subject of a security observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "type", content = "details", rename_all = "snake_case")]
pub enum TargetDescriptor {
    /// Host-level observation.
    Host { hostname: String },
    /// Process-level observation.
    Process {
        pid: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        executable_path: Option<String>,
    },
    /// Socket / listening port observation.
    Socket {
        protocol: SocketProtocol,
        port: u16,
        bind_address: String,
    },
    /// Firewall profile observation.
    Firewall { profile: String },
    /// Local user / account observation.
    User {
        username: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        uid_or_sid: Option<String>,
    },
    /// Operating system background service / daemon.
    Service { service_name: String },
    /// Operating system security configuration check.
    OsConfiguration { check_name: String },
}

impl TargetDescriptor {
    /// Generates a canonical, deterministic string key for deduplication and findings fingerprints.
    pub fn target_key(&self) -> String {
        match self {
            Self::Host { hostname } => format!("host:{}", hostname.to_lowercase()),
            Self::Process { pid, .. } => format!("process:{}", pid),
            Self::Socket {
                protocol,
                port,
                bind_address,
            } => format!("socket:{}:{}:{}", protocol, bind_address, port),
            Self::Firewall { profile } => format!("firewall:{}", profile.to_lowercase()),
            Self::User { username, .. } => format!("user:{}", username.to_lowercase()),
            Self::Service { service_name } => format!("service:{}", service_name.to_lowercase()),
            Self::OsConfiguration { check_name } => {
                format!("os_config:{}", check_name.to_lowercase())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_descriptor_keys() {
        let host = TargetDescriptor::Host {
            hostname: "DESKTOP-TEST".to_string(),
        };
        assert_eq!(host.target_key(), "host:desktop-test");

        let socket = TargetDescriptor::Socket {
            protocol: SocketProtocol::Tcp,
            port: 80,
            bind_address: "0.0.0.0".to_string(),
        };
        assert_eq!(socket.target_key(), "socket:tcp:0.0.0.0:80");

        let proc = TargetDescriptor::Process {
            pid: 1337,
            executable_path: Some("C:\\bin\\app.exe".to_string()),
        };
        assert_eq!(proc.target_key(), "process:1337");

        let user = TargetDescriptor::User {
            username: "Administrator".to_string(),
            uid_or_sid: None,
        };
        assert_eq!(user.target_key(), "user:administrator");
    }

    #[test]
    fn test_target_descriptor_serialization() {
        let desc = TargetDescriptor::Socket {
            protocol: SocketProtocol::Tcp,
            port: 443,
            bind_address: "127.0.0.1".to_string(),
        };
        let json = serde_json::to_string(&desc).unwrap();
        assert!(json.contains("\"type\":\"socket\""));
        assert!(json.contains("\"port\":443"));

        let deserialized: TargetDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(desc, deserialized);
    }
}
