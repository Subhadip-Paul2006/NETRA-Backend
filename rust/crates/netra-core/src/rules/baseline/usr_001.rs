use crate::observation::{Observation, ObservationPayload, ObservationType, TargetDescriptor};
use crate::rules::traits::{FindingRule, RawFinding};
use crate::storage::FindingSeverity;

/// Rule USR-001: Detects active built-in Guest user account.
pub struct Usr001GuestEnabledRule;

impl FindingRule for Usr001GuestEnabledRule {
    fn rule_id(&self) -> &'static str {
        "USR-001-GUEST-ENABLED"
    }

    fn version(&self) -> u32 {
        1
    }

    fn domain(&self) -> ObservationType {
        ObservationType::Users
    }

    fn default_severity(&self) -> FindingSeverity {
        FindingSeverity::Medium
    }

    fn evaluate(&self, obs: &Observation) -> Vec<RawFinding> {
        let mut findings = Vec::new();

        if let ObservationPayload::Users(ref payload) = obs.payload {
            for user in &payload.users {
                let is_guest = user.username.eq_ignore_ascii_case("Guest")
                    || user.uid_or_sid == "S-1-5-32-546"
                    || user.uid_or_sid == "guest";

                if is_guest && user.is_enabled {
                    findings.push(RawFinding {
                        title: "Built-in Guest Account Is Enabled".to_string(),
                        description: format!(
                            "The built-in Guest account (username: '{}', ID: '{}') is active, allowing unauthenticated or anonymous access.",
                            user.username, user.uid_or_sid
                        ),
                        severity: self.default_severity(),
                        target: TargetDescriptor::User {
                            username: user.username.clone(),
                            uid_or_sid: Some(user.uid_or_sid.clone()),
                        },
                        discriminator: user.username.clone(),
                        remediation_guidance: Some(
                            "Disable the built-in Guest account in local account security policy.".to_string(),
                        ),
                        raw_evidence: serde_json::json!({
                            "username": user.username,
                            "uid_or_sid": user.uid_or_sid,
                            "is_enabled": user.is_enabled,
                            "is_admin": user.is_admin,
                        }),
                    });
                }
            }
        }

        findings
    }
}
