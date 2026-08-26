use crate::observation::{
    Observation, ObservationPayload, ObservationType, SocketProtocol, TargetDescriptor,
};
use crate::rules::traits::{FindingRule, RawFinding};
use crate::storage::FindingSeverity;

/// Rule NET-002: Detects database engines exposed to wildcard network interfaces.
pub struct Net002UnrestrictedDbRule;

impl FindingRule for Net002UnrestrictedDbRule {
    fn rule_id(&self) -> &'static str {
        "NET-002-UNRESTRICTED-DB"
    }

    fn version(&self) -> u32 {
        1
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Sockets
    }

    fn default_severity(&self) -> FindingSeverity {
        FindingSeverity::Critical
    }

    fn evaluate(&self, obs: &Observation) -> Vec<RawFinding> {
        let mut findings = Vec::new();

        if let ObservationPayload::Sockets(ref payload) = obs.payload {
            for sock in &payload.sockets {
                if sock.protocol == SocketProtocol::Tcp && sock.state == "LISTEN" {
                    let is_wildcard = sock.local_address == "0.0.0.0"
                        || sock.local_address == "::"
                        || sock.local_address.is_empty();

                    let is_db_port = sock.local_port == 5432   // PostgreSQL
                        || sock.local_port == 3306             // MySQL / MariaDB
                        || sock.local_port == 27017            // MongoDB
                        || sock.local_port == 6379             // Redis
                        || sock.local_port == 1433; // Microsoft SQL Server

                    if is_wildcard && is_db_port {
                        let db_name = match sock.local_port {
                            5432 => "PostgreSQL",
                            3306 => "MySQL/MariaDB",
                            27017 => "MongoDB",
                            6379 => "Redis",
                            1433 => "MS SQL Server",
                            _ => "Database",
                        };

                        findings.push(RawFinding {
                            title: format!("Unrestricted {} Database Exposed on Port {}", db_name, sock.local_port),
                            description: format!(
                                "Database server ({}) is bound to wildcard interface '{}:{}' (PID {}), exposing it to network-wide access.",
                                db_name, sock.local_address, sock.local_port, sock.owning_pid
                            ),
                            severity: self.default_severity(),
                            target: TargetDescriptor::Socket {
                                protocol: sock.protocol,
                                port: sock.local_port,
                                bind_address: sock.local_address.clone(),
                            },
                            discriminator: format!("{}:{}", sock.local_address, sock.local_port),
                            remediation_guidance: Some(
                                "Bind the database listener strictly to 127.0.0.1 or an isolated private management subnet with TLS authentication."
                                    .to_string(),
                            ),
                            raw_evidence: serde_json::json!({
                                "database": db_name,
                                "local_address": sock.local_address,
                                "local_port": sock.local_port,
                                "owning_pid": sock.owning_pid,
                                "protocol": sock.protocol,
                            }),
                        });
                    }
                }
            }
        }

        findings
    }
}
