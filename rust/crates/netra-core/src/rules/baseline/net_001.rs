use crate::observation::{
    Observation, ObservationPayload, ObservationType, SocketProtocol, TargetDescriptor,
};
use crate::rules::traits::{FindingRule, RawFinding};
use crate::storage::FindingSeverity;

/// Rule NET-001: Detects unencrypted plaintext management/web service ports listening on wildcard addresses.
pub struct Net001PlaintextPortRule;

impl FindingRule for Net001PlaintextPortRule {
    fn rule_id(&self) -> &'static str {
        "NET-001-PLAINTEXT-PORT"
    }

    fn version(&self) -> u32 {
        1
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Sockets
    }

    fn default_severity(&self) -> FindingSeverity {
        FindingSeverity::High
    }

    fn evaluate(&self, obs: &Observation) -> Vec<RawFinding> {
        let mut findings = Vec::new();

        if let ObservationPayload::Sockets(ref payload) = obs.payload {
            for sock in &payload.sockets {
                if sock.protocol == SocketProtocol::Tcp && sock.state == "LISTEN" {
                    let is_wildcard = sock.local_address == "0.0.0.0"
                        || sock.local_address == "::"
                        || sock.local_address.is_empty();

                    let is_plaintext_port =
                        sock.local_port == 80 || sock.local_port == 21 || sock.local_port == 23;

                    if is_wildcard && is_plaintext_port {
                        findings.push(RawFinding {
                            title: format!("Unencrypted Plaintext Service on Port {}", sock.local_port),
                            description: format!(
                                "Socket listening on wildcard address '{}:{}' transmitting cleartext traffic (PID {}).",
                                sock.local_address, sock.local_port, sock.owning_pid
                            ),
                            severity: self.default_severity(),
                            target: TargetDescriptor::Socket {
                                protocol: sock.protocol,
                                port: sock.local_port,
                                bind_address: sock.local_address.clone(),
                            },
                            discriminator: format!("{}:{}", sock.local_address, sock.local_port),
                            remediation_guidance: Some(
                                "Upgrade the service to use TLS/HTTPS or bind strictly to loopback (127.0.0.1)."
                                    .to_string(),
                            ),
                            raw_evidence: serde_json::json!({
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
