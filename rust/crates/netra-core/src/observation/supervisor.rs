//! Scanner Supervisor managing concurrent scanner execution, timeouts, panic isolation, and batch database writes.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{error, info, warn};

use crate::error::{NetraError, Result};
use crate::id::DeviceId;
use crate::observation::models::ObservationType;
use crate::observation::traits::PostureScanner;
use crate::rules::RuleEngine;
use crate::storage::repositories::findings::FindingsRepository;
use crate::storage::repositories::queue::ObservationQueueRepository;
use crate::storage::{DatabaseEngine, FindingEntry, FindingStatus};

/// Hard per-collector safety execution timeout (5000ms).
pub const SCANNER_TIMEOUT_MS: u64 = 5000;

/// Result summary of a completed scan cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCycleResult {
    pub total_scanners: usize,
    pub successful_scanners: usize,
    pub observations_collected: usize,
    pub findings_evaluated: usize,
    pub active_open_findings: usize,
    pub duration_ms: u64,
}

/// Orchestrates host security posture scanners and persists normalized observations and findings.
pub struct ScannerSupervisor {
    storage: Arc<DatabaseEngine>,
    scanners: Vec<Arc<dyn PostureScanner>>,
    rule_engine: Arc<RuleEngine>,
}

impl ScannerSupervisor {
    /// Creates a new ScannerSupervisor with the given database engine and collectors.
    pub fn new(storage: Arc<DatabaseEngine>, scanners: Vec<Arc<dyn PostureScanner>>) -> Self {
        Self {
            storage,
            scanners,
            rule_engine: Arc::new(RuleEngine::with_baseline_rules()),
        }
    }

    /// Creates a ScannerSupervisor with a custom RuleEngine.
    pub fn with_rule_engine(
        storage: Arc<DatabaseEngine>,
        scanners: Vec<Arc<dyn PostureScanner>>,
        rule_engine: Arc<RuleEngine>,
    ) -> Self {
        Self {
            storage,
            scanners,
            rule_engine,
        }
    }

    /// Executes all registered scanners concurrently with timeout isolation.
    pub async fn run_scan_cycle(&self, device_id: &DeviceId) -> Result<ScanCycleResult> {
        let start = Instant::now();
        let total_scanners = self.scanners.len();
        let mut observations = Vec::new();

        info!(
            total_scanners = total_scanners,
            "Initiating host security posture scan cycle"
        );

        // 1. Run collectors concurrently with per-collector timeout
        let mut join_set = tokio::task::JoinSet::new();

        for scanner in &self.scanners {
            let sc = Arc::clone(scanner);
            let d_id = device_id.clone();
            join_set.spawn(async move {
                let scanner_id = sc.scanner_id();
                let res = timeout(Duration::from_millis(SCANNER_TIMEOUT_MS), sc.scan(&d_id)).await;

                match res {
                    Ok(Ok(obs)) => Ok(obs),
                    Ok(Err(e)) => {
                        error!(scanner_id = scanner_id, error = %e, "Scanner execution failed");
                        Err(e)
                    }
                    Err(_) => {
                        warn!(
                            scanner_id = scanner_id,
                            timeout_ms = SCANNER_TIMEOUT_MS,
                            "Scanner timed out"
                        );
                        Err(NetraError::timeout("scanner_execution", SCANNER_TIMEOUT_MS))
                    }
                }
            });
        }

        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(Ok(obs)) => observations.push(obs),
                Ok(Err(_)) => {} // Individual failure logged
                Err(join_err) => {
                    error!(error = %join_err, "Scanner task panicked or failed to join");
                }
            }
        }

        let successful_scanners = observations.len();

        // 2. Evaluate observations against RuleEngine and persist batch into SQLite
        let mut all_findings: Vec<FindingEntry> = Vec::new();
        for obs in &observations {
            let findings = self.rule_engine.evaluate(obs);
            all_findings.extend(findings);
        }

        let findings_evaluated = all_findings.len();

        // 3. Perform batch SQLite write
        let obs_clone = observations.clone();
        let findings_clone = all_findings.clone();

        self.storage
            .with_writer(move |conn| {
                // Enqueue observations
                for obs in &obs_clone {
                    let payload_str =
                        serde_json::to_string(&obs.payload).unwrap_or_else(|_| "{}".to_string());
                    let obs_type = format!("{:?}", obs.observation_type).to_lowercase();
                    let _ =
                        ObservationQueueRepository::enqueue(conn, &obs_type, &payload_str, None);
                }

                // Upsert findings
                for f in &findings_clone {
                    let parsed: serde_json::Value = serde_json::from_str(&f.evidence_summary_json)
                        .unwrap_or_else(|_| serde_json::json!({}));
                    let target_key = parsed["target_key"].as_str().unwrap_or("").to_string();

                    let _ = FindingsRepository::upsert(
                        conn,
                        &f.rule_id,
                        f.severity,
                        &target_key,
                        &f.rule_id,
                        &f.title,
                        &f.evidence_summary_json,
                    );
                }

                Ok(())
            })
            .await
            .map_err(|e| {
                NetraError::storage(format!("Failed to persist scan cycle results: {}", e))
            })?;

        // 4. Query current open findings count
        let open_findings = self
            .storage
            .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
            .await
            .map_err(|e| NetraError::storage(format!("Failed to query open findings: {}", e)))?;

        let duration_ms = start.elapsed().as_millis() as u64;

        info!(
            successful_scanners = successful_scanners,
            observations = observations.len(),
            findings_evaluated = findings_evaluated,
            open_findings = open_findings.len(),
            duration_ms = duration_ms,
            "Completed host security posture scan cycle"
        );

        Ok(ScanCycleResult {
            total_scanners,
            successful_scanners,
            observations_collected: observations.len(),
            findings_evaluated,
            active_open_findings: open_findings.len(),
            duration_ms,
        })
    }

    /// Executes a single scanner domain.
    pub async fn run_single_domain_scan(
        &self,
        domain: ObservationType,
        device_id: &DeviceId,
    ) -> Result<ScanCycleResult> {
        let scanner = self
            .scanners
            .iter()
            .find(|s| s.domain() == domain)
            .ok_or_else(|| {
                NetraError::platform(format!("No scanner registered for domain '{:?}'", domain))
            })?;

        let start = Instant::now();
        let obs = scanner.scan(device_id).await?;
        let findings = self.rule_engine.evaluate(&obs);

        let obs_clone = vec![obs.clone()];
        let findings_clone = findings.clone();

        self.storage
            .with_writer(move |conn| {
                for o in &obs_clone {
                    let payload_str =
                        serde_json::to_string(&o.payload).unwrap_or_else(|_| "{}".to_string());
                    let obs_type = format!("{:?}", o.observation_type).to_lowercase();
                    let _ =
                        ObservationQueueRepository::enqueue(conn, &obs_type, &payload_str, None);
                }

                for f in &findings_clone {
                    let parsed: serde_json::Value = serde_json::from_str(&f.evidence_summary_json)
                        .unwrap_or_else(|_| serde_json::json!({}));
                    let target_key = parsed["target_key"].as_str().unwrap_or("").to_string();

                    let _ = FindingsRepository::upsert(
                        conn,
                        &f.rule_id,
                        f.severity,
                        &target_key,
                        &f.rule_id,
                        &f.title,
                        &f.evidence_summary_json,
                    );
                }

                Ok(())
            })
            .await
            .map_err(|e| NetraError::storage(format!("Failed to persist domain scan: {}", e)))?;

        let open_findings = self
            .storage
            .with_reader(|conn| FindingsRepository::list_by_status(conn, FindingStatus::Open))
            .await
            .map_err(|e| NetraError::storage(format!("Failed to query open findings: {}", e)))?;

        Ok(ScanCycleResult {
            total_scanners: 1,
            successful_scanners: 1,
            observations_collected: 1,
            findings_evaluated: findings.len(),
            active_open_findings: open_findings.len(),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::models::*;
    use crate::observation::payloads::*;
    use crate::observation::target::TargetDescriptor;
    use async_trait::async_trait;

    struct MockSocketScanner;

    #[async_trait]
    impl PostureScanner for MockSocketScanner {
        fn scanner_id(&self) -> &'static str {
            "mock.sockets"
        }

        fn domain(&self) -> ObservationType {
            ObservationType::Sockets
        }

        async fn scan(&self, device_id: &DeviceId) -> Result<Observation> {
            Observation::new(
                device_id.clone(),
                self.scanner_id(),
                self.domain(),
                TargetDescriptor::Host {
                    hostname: "mock-host".to_string(),
                },
                5,
                PrivilegeStatus::Available,
                ConfidenceScore::KERNEL_AUTHORITATIVE,
                SensitivityLevel::Public,
                ObservationPayload::Sockets(SocketObservationPayload {
                    sockets: vec![SocketRecord {
                        protocol: SocketProtocol::Tcp,
                        local_address: "0.0.0.0".to_string(),
                        local_port: 80,
                        remote_address: None,
                        remote_port: None,
                        state: "LISTEN".to_string(),
                        owning_pid: 10,
                        process_name: None,
                    }],
                }),
            )
        }
    }

    #[tokio::test]
    async fn test_scanner_supervisor_full_cycle() {
        let storage = Arc::new(DatabaseEngine::in_memory().unwrap());
        let supervisor = ScannerSupervisor::new(storage.clone(), vec![Arc::new(MockSocketScanner)]);

        let device_id = DeviceId::new();
        let result = supervisor.run_scan_cycle(&device_id).await.unwrap();

        assert_eq!(result.total_scanners, 1);
        assert_eq!(result.successful_scanners, 1);
        assert_eq!(result.observations_collected, 1);
        assert_eq!(result.findings_evaluated, 1);
        assert_eq!(result.active_open_findings, 1);
    }
}
