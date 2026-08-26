use crate::observation::{Observation, ObservationPayload, ObservationType, TargetDescriptor};
use crate::rules::traits::{FindingRule, RawFinding};
use crate::storage::FindingSeverity;

/// Rule SVC-001: Detects Windows service binary paths containing spaces without enclosing quotes.
pub struct Svc001UnquotedPathRule;

impl FindingRule for Svc001UnquotedPathRule {
    fn rule_id(&self) -> &'static str {
        "SVC-001-UNQUOTED-PATH"
    }

    fn version(&self) -> u32 {
        1
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Services
    }

    fn default_severity(&self) -> FindingSeverity {
        FindingSeverity::Low
    }

    fn evaluate(&self, obs: &Observation) -> Vec<RawFinding> {
        let mut findings = Vec::new();

        if let ObservationPayload::Services(ref payload) = obs.payload {
            for svc in &payload.services {
                if let Some(ref path) = svc.binary_path {
                    // Check if path contains whitespace and does not start and end with quotes
                    let has_spaces = path.contains(' ');
                    let is_quoted = path.starts_with('"') && path.ends_with('"');
                    let is_windows_path =
                        path.contains('\\') || path.to_lowercase().ends_with(".exe");

                    if has_spaces && !is_quoted && is_windows_path {
                        findings.push(RawFinding {
                            title: format!("Unquoted Service Path for '{}'", svc.service_name),
                            description: format!(
                                "Service '{}' has binary path containing spaces without enclosing quotes: '{}'. This presents a local privilege escalation vector.",
                                svc.service_name, path
                            ),
                            severity: self.default_severity(),
                            target: TargetDescriptor::Service {
                                service_name: svc.service_name.clone(),
                            },
                            discriminator: svc.service_name.clone(),
                            remediation_guidance: Some(
                                format!("Enclose the service binary path in quotes: '\"{}\"'", path),
                            ),
                            raw_evidence: serde_json::json!({
                                "service_name": svc.service_name,
                                "binary_path": path,
                                "state": svc.state,
                                "start_type": svc.start_type,
                            }),
                        });
                    }
                }
            }
        }

        findings
    }
}
