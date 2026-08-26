use crate::observation::{Observation, ObservationPayload, ObservationType, TargetDescriptor};
use crate::rules::traits::{FindingRule, RawFinding};
use crate::storage::FindingSeverity;

/// Rule FW-001: Detects disabled host firewall profiles.
pub struct Fw001ProfileDisabledRule;

impl FindingRule for Fw001ProfileDisabledRule {
    fn rule_id(&self) -> &'static str {
        "FW-001-PROFILE-DISABLED"
    }

    fn version(&self) -> u32 {
        1
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Firewall
    }

    fn default_severity(&self) -> FindingSeverity {
        FindingSeverity::Critical
    }

    fn evaluate(&self, obs: &Observation) -> Vec<RawFinding> {
        let mut findings = Vec::new();

        if let ObservationPayload::Firewall(ref payload) = obs.payload {
            for prof in &payload.profiles {
                if !prof.is_enabled {
                    findings.push(RawFinding {
                        title: format!("Host Firewall Profile '{}' Disabled", prof.profile_name),
                        description: format!(
                            "The '{}' firewall profile is currently disabled, permitting unfiltered inbound and outbound traffic.",
                            prof.profile_name
                        ),
                        severity: self.default_severity(),
                        target: TargetDescriptor::Firewall {
                            profile: prof.profile_name.clone(),
                        },
                        discriminator: prof.profile_name.clone(),
                        remediation_guidance: Some(
                            format!("Enable the '{}' firewall profile in host firewall settings.", prof.profile_name),
                        ),
                        raw_evidence: serde_json::json!({
                            "profile_name": prof.profile_name,
                            "is_enabled": prof.is_enabled,
                            "default_inbound_action": prof.default_inbound_action,
                            "default_outbound_action": prof.default_outbound_action,
                        }),
                    });
                }
            }
        }

        findings
    }
}
