use crate::observation::{Observation, ObservationPayload, ObservationType, TargetDescriptor};
use crate::rules::traits::{FindingRule, RawFinding};
use crate::storage::FindingSeverity;

/// Rule OS-001: Detects disabled UEFI Secure Boot on supported host platforms.
pub struct Os001SecureBootOffRule;

impl FindingRule for Os001SecureBootOffRule {
    fn rule_id(&self) -> &'static str {
        "OS-001-SECUREBOOT-OFF"
    }

    fn version(&self) -> u32 {
        1
    }

    fn domain(&self) -> ObservationType {
        ObservationType::OsConfig
    }

    fn default_severity(&self) -> FindingSeverity {
        FindingSeverity::High
    }

    fn evaluate(&self, obs: &Observation) -> Vec<RawFinding> {
        let mut findings = Vec::new();

        if let ObservationPayload::OsConfig(ref payload) = obs.payload {
            for cfg in &payload.configurations {
                if cfg.check_name.eq_ignore_ascii_case("SecureBoot") {
                    let is_disabled = cfg.value == "0"
                        || cfg.value.eq_ignore_ascii_case("disabled")
                        || cfg.value.eq_ignore_ascii_case("false");

                    if is_disabled {
                        findings.push(RawFinding {
                            title: "UEFI Secure Boot Is Disabled".to_string(),
                            description: "UEFI Secure Boot verification is currently disabled on this system, leaving boot components vulnerable to firmware rootkits.".to_string(),
                            severity: self.default_severity(),
                            target: TargetDescriptor::OsConfiguration {
                                check_name: "SecureBoot".to_string(),
                            },
                            discriminator: "SecureBoot".to_string(),
                            remediation_guidance: Some(
                                "Enable UEFI Secure Boot in system BIOS/UEFI firmware settings.".to_string(),
                            ),
                            raw_evidence: serde_json::json!({
                                "check_name": cfg.check_name,
                                "status": cfg.status,
                                "value": cfg.value,
                                "details": cfg.details,
                            }),
                        });
                    }
                }
            }
        }

        findings
    }
}
