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
    /// Network interface target.
    NetworkInterface { interface_name: String },
    /// Network routing entry target.
    Route {
        destination: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        gateway: Option<String>,
    },
    /// Configured DNS nameserver target.
    DnsServer { server_address: String },
    /// Passive Layer-2 / Layer-3 network neighbor target.
    NetworkNeighbor {
        ip_address: String,
        interface_name: String,
    },
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
            Self::NetworkInterface { interface_name } => {
                format!("interface:{}", interface_name.to_lowercase())
            }
            Self::Route {
                destination,
                gateway,
            } => {
                format!(
                    "route:{}:{}",
                    destination.to_lowercase(),
                    gateway.as_deref().unwrap_or("direct").to_lowercase()
                )
            }
            Self::DnsServer { server_address } => {
                format!("dns_server:{}", server_address.to_lowercase())
            }
            Self::NetworkNeighbor {
                ip_address,
                interface_name,
            } => {
                format!(
                    "neighbor:{}:{}",
                    interface_name.to_lowercase(),
                    ip_address.to_lowercase()
                )
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

        let iface = TargetDescriptor::NetworkInterface {
            interface_name: "Ethernet0".to_string(),
        };
        assert_eq!(iface.target_key(), "interface:ethernet0");

        let route = TargetDescriptor::Route {
            destination: "0.0.0.0/0".to_string(),
            gateway: Some("192.168.1.1".to_string()),
        };
        assert_eq!(route.target_key(), "route:0.0.0.0/0:192.168.1.1");

        let dns = TargetDescriptor::DnsServer {
            server_address: "8.8.8.8".to_string(),
        };
        assert_eq!(dns.target_key(), "dns_server:8.8.8.8");

        let neighbor = TargetDescriptor::NetworkNeighbor {
            ip_address: "192.168.1.50".to_string(),
            interface_name: "eth0".to_string(),
        };
        assert_eq!(neighbor.target_key(), "neighbor:eth0:192.168.1.50");
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

        let iface_desc = TargetDescriptor::NetworkInterface {
            interface_name: "eth0".to_string(),
        };
        let iface_json = serde_json::to_string(&iface_desc).unwrap();
        assert!(iface_json.contains("\"type\":\"network_interface\""));
        let deserialized_iface: TargetDescriptor = serde_json::from_str(&iface_json).unwrap();
        assert_eq!(iface_desc, deserialized_iface);
    }
}
