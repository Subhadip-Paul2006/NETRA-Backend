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

    /// Creates a RuleEngine configured with all baseline rules and network security finding rules (Phase 8.7).
    pub fn with_all_rules() -> Self {
        let mut engine = Self::with_baseline_rules();
        for rule in crate::rules::network::create_all_network_rules() {
            engine.register_rule(rule);
        }
        engine
    }

    /// Registers a custom or baseline rule with the engine.
    pub fn register_rule(&mut self, rule: Arc<dyn FindingRule>) {
        self.rules.push(rule);
    }

    /// Returns a slice of the registered rules in this engine.
    pub fn rules(&self) -> &[Arc<dyn FindingRule>] {
        &self.rules
    }

    /// Known registered full rule IDs across NETRA baseline and network domains.
    pub const REGISTERED_RULE_IDS: &'static [&'static str] = &[
        "NET-001-PLAINTEXT-PORT",
        "NET-002-UNRESTRICTED-DB",
        "FW-001-PROFILE-DISABLED",
        "USR-001-GUEST-ENABLED",
        "SVC-001-UNQUOTED-PATH",
        "OS-001-SECUREBOOT-OFF",
        "NET-003-GATEWAY-OFF-SUBNET",
        "NET-004-COMPETING-DEFAULT-GATEWAYS",
        "NET-005-INVALID-DNS-RESOLVER",
        "NET-006-LOOPBACK-ROUTE-LEAK",
        "NET-007-INVALID-NEIGHBOR-ENTRY",
        "NET-008-MULTI-HOMED-PUBLIC-PRIVATE",
    ];

    /// Deterministically resolves a full registered rule ID or canonical short rule ID.
    ///
    /// # Resolution Rules:
    /// - **Full registered rule ID**: Exact (case-insensitive) match, e.g. `"NET-003-GATEWAY-OFF-SUBNET"` -> `Some("NET-003-GATEWAY-OFF-SUBNET".to_string())`.
    /// - **Canonical short rule ID**: Format `^[A-Z]{2,4}-[0-9]{3}$` (e.g. `"NET-003"`, `"FW-001"`) resolves to the matching registered rule ID.
    /// - **Arbitrary partial strings**: E.g. `"NET-00"`, `"NET"`, `"GATEWAY"` return `None` (prohibiting broad substring matching).
    /// - **Unknown / Ambiguous rules**: E.g. `"XYZ-999"` return `None`.
    pub fn resolve_rule_id(input: &str) -> Option<String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return None;
        }

        let upper = trimmed.to_ascii_uppercase();

        // 1. Exact match against full rule ID
        for &rule in Self::REGISTERED_RULE_IDS {
            if upper == rule {
                return Some(rule.to_string());
            }
        }

        // 2. Canonical short rule ID: prefix (2..=4 alphabetic) + '-' + 3 digits (e.g. NET-003, FW-001, USR-001, OS-001)
        let parts: Vec<&str> = upper.split('-').collect();
        if parts.len() == 2 {
            let prefix = parts[0];
            let num = parts[1];
            if (2..=4).contains(&prefix.len())
                && prefix.chars().all(|c| c.is_ascii_alphabetic())
                && num.len() == 3
                && num.chars().all(|c| c.is_ascii_digit())
            {
                let search_prefix = format!("{}-", upper);
                for &rule in Self::REGISTERED_RULE_IDS {
                    if rule.starts_with(&search_prefix) {
                        return Some(rule.to_string());
                    }
                }
            }
        }

        None
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

    #[test]
    fn test_resolve_rule_id_deterministic() {
        // 1. Full exact matches
        assert_eq!(
            RuleEngine::resolve_rule_id("NET-003-GATEWAY-OFF-SUBNET"),
            Some("NET-003-GATEWAY-OFF-SUBNET".to_string())
        );
        assert_eq!(
            RuleEngine::resolve_rule_id("net-003-gateway-off-subnet"),
            Some("NET-003-GATEWAY-OFF-SUBNET".to_string())
        );
        assert_eq!(
            RuleEngine::resolve_rule_id("FW-001-PROFILE-DISABLED"),
            Some("FW-001-PROFILE-DISABLED".to_string())
        );

        // 2. Canonical short IDs
        assert_eq!(
            RuleEngine::resolve_rule_id("NET-001"),
            Some("NET-001-PLAINTEXT-PORT".to_string())
        );
        assert_eq!(
            RuleEngine::resolve_rule_id("net-001"),
            Some("NET-001-PLAINTEXT-PORT".to_string())
        );
        assert_eq!(
            RuleEngine::resolve_rule_id("NET-003"),
            Some("NET-003-GATEWAY-OFF-SUBNET".to_string())
        );
        assert_eq!(
            RuleEngine::resolve_rule_id("NET-004"),
            Some("NET-004-COMPETING-DEFAULT-GATEWAYS".to_string())
        );
        assert_eq!(
            RuleEngine::resolve_rule_id("NET-005"),
            Some("NET-005-INVALID-DNS-RESOLVER".to_string())
        );
        assert_eq!(
            RuleEngine::resolve_rule_id("NET-006"),
            Some("NET-006-LOOPBACK-ROUTE-LEAK".to_string())
        );
        assert_eq!(
            RuleEngine::resolve_rule_id("NET-007"),
            Some("NET-007-INVALID-NEIGHBOR-ENTRY".to_string())
        );
        assert_eq!(
            RuleEngine::resolve_rule_id("NET-008"),
            Some("NET-008-MULTI-HOMED-PUBLIC-PRIVATE".to_string())
        );
        assert_eq!(
            RuleEngine::resolve_rule_id("FW-001"),
            Some("FW-001-PROFILE-DISABLED".to_string())
        );
        assert_eq!(
            RuleEngine::resolve_rule_id("USR-001"),
            Some("USR-001-GUEST-ENABLED".to_string())
        );
        assert_eq!(
            RuleEngine::resolve_rule_id("SVC-001"),
            Some("SVC-001-UNQUOTED-PATH".to_string())
        );
        assert_eq!(
            RuleEngine::resolve_rule_id("OS-001"),
            Some("OS-001-SECUREBOOT-OFF".to_string())
        );

        // 3. Prohibited arbitrary partial strings -> None
        assert_eq!(RuleEngine::resolve_rule_id("NET-00"), None);
        assert_eq!(RuleEngine::resolve_rule_id("NET"), None);
        assert_eq!(RuleEngine::resolve_rule_id("GATEWAY"), None);
        assert_eq!(RuleEngine::resolve_rule_id("NET-003-GATEWAY"), None);
        assert_eq!(RuleEngine::resolve_rule_id("OFF-SUBNET"), None);

        // 4. Unknown canonical IDs -> None
        assert_eq!(RuleEngine::resolve_rule_id("XYZ-999"), None);
        assert_eq!(RuleEngine::resolve_rule_id("NET-999"), None);

        // 5. Empty/whitespace input -> None
        assert_eq!(RuleEngine::resolve_rule_id(""), None);
        assert_eq!(RuleEngine::resolve_rule_id("   "), None);
    }
}
