use std::sync::Arc;

use crate::observation::Observation;
use crate::rules::baseline::*;
use crate::rules::traits::FindingRule;
use crate::storage::repositories::findings::FindingsRepository;
use crate::storage::{FindingEntry, FindingStatus};

/// Evaluates normalized observations against security posture rules and produces deduplicated finding records.
#[derive(Default)]
pub struct RuleEngine {
    rules: Vec<Arc<dyn FindingRule>>,
}

impl RuleEngine {
    /// Creates an empty RuleEngine.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Creates a RuleEngine pre-configured with all Phase 7 baseline security rules.
    pub fn with_baseline_rules() -> Self {
        let mut engine = Self::new();
        engine.register_rule(Arc::new(Net001PlaintextPortRule));
        engine.register_rule(Arc::new(Net002UnrestrictedDbRule));
        engine.register_rule(Arc::new(Fw001ProfileDisabledRule));
        engine.register_rule(Arc::new(Usr001GuestEnabledRule));
        engine.register_rule(Arc::new(Svc001UnquotedPathRule));
        engine.register_rule(Arc::new(Os001SecureBootOffRule));
        engine
    }

    /// Registers a custom or baseline rule with the engine.
    pub fn register_rule(&mut self, rule: Arc<dyn FindingRule>) {
        self.rules.push(rule);
    }

    /// Computes the deterministic SHA-256 deduplication fingerprint for a finding.
    pub fn compute_fingerprint(rule_id: &str, target_key: &str, discriminator: &str) -> String {
        FindingsRepository::compute_fingerprint(rule_id, target_key, discriminator)
    }

    /// Evaluates an observation against all matching rules and produces structured [`FindingEntry`] objects.
    pub fn evaluate(&self, obs: &Observation) -> Vec<FindingEntry> {
        let mut entries = Vec::new();
        let now_str = obs.collected_at.to_rfc3339();

        for rule in &self.rules {
            if rule.domain() == obs.observation_type {
                let raw_findings = rule.evaluate(obs);
                for raw in raw_findings {
                    let target_key = raw.target.target_key();
                    let fingerprint =
                        Self::compute_fingerprint(rule.rule_id(), &target_key, &raw.discriminator);

                    let summary_json = serde_json::json!({
                        "description": raw.description,
                        "target": raw.target,
                        "target_key": target_key,
                        "remediation": raw.remediation_guidance,
                        "evidence": raw.raw_evidence,
                    });

                    let evidence_summary_json =
                        serde_json::to_string(&summary_json).unwrap_or_else(|_| "{}".to_string());

                    let entry = FindingEntry {
                        fingerprint,
                        rule_id: rule.rule_id().to_string(),
                        severity: raw.severity,
                        status: FindingStatus::Open,
                        title: raw.title,
                        evidence_summary_json,
                        occurrence_count: 1,
                        first_seen: now_str.clone(),
                        last_seen: now_str.clone(),
                    };

                    entries.push(entry);
                }
            }
        }

        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::DeviceId;
    use crate::observation::*;

    #[test]
    fn test_rule_engine_evaluation_and_fingerprinting() {
        let engine = RuleEngine::with_baseline_rules();
        let device_id = DeviceId::new();

        let payload = ObservationPayload::Sockets(SocketObservationPayload {
            sockets: vec![
                SocketRecord {
                    protocol: SocketProtocol::Tcp,
                    local_address: "0.0.0.0".to_string(),
                    local_port: 80,
                    remote_address: None,
                    remote_port: None,
                    state: "LISTEN".to_string(),
                    owning_pid: 1234,
                    process_name: Some("httpd.exe".to_string()),
                },
                SocketRecord {
                    protocol: SocketProtocol::Tcp,
                    local_address: "0.0.0.0".to_string(),
                    local_port: 5432,
                    remote_address: None,
                    remote_port: None,
                    state: "LISTEN".to_string(),
                    owning_pid: 5678,
                    process_name: Some("postgres.exe".to_string()),
                },
                SocketRecord {
                    protocol: SocketProtocol::Tcp,
                    local_address: "127.0.0.1".to_string(),
                    local_port: 8080,
                    remote_address: None,
                    remote_port: None,
                    state: "LISTEN".to_string(),
                    owning_pid: 9999,
                    process_name: None,
                },
            ],
        });

        let obs = Observation::new(
            device_id.clone(),
            "scanner.sockets.v1",
            ObservationType::Sockets,
            TargetDescriptor::Host {
                hostname: "test-host".to_string(),
            },
            10,
            PrivilegeStatus::Available,
            ConfidenceScore::KERNEL_AUTHORITATIVE,
            SensitivityLevel::Public,
            payload,
        )
        .unwrap();

        let findings = engine.evaluate(&obs);
        assert_eq!(findings.len(), 2); // NET-001 (port 80) and NET-002 (port 5432)

        let net001 = findings
            .iter()
            .find(|f| f.rule_id == "NET-001-PLAINTEXT-PORT")
            .unwrap();
        assert_eq!(net001.severity, crate::storage::FindingSeverity::High);
        assert_eq!(net001.fingerprint.len(), 64);

        let net002 = findings
            .iter()
            .find(|f| f.rule_id == "NET-002-UNRESTRICTED-DB")
            .unwrap();
        assert_eq!(net002.severity, crate::storage::FindingSeverity::Critical);
        assert_eq!(net002.fingerprint.len(), 64);
    }
}
