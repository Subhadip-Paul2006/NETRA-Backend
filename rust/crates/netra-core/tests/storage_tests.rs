use netra_core::config::StorageConfig;
use netra_core::runtime::{ComponentHealth, RuntimeCoordinator};
use netra_core::storage::{
    CleanShutdownMarker, ConfigRepository, DatabaseEngine, FindingSeverity, FindingStatus,
    FindingsRepository, ObservationQueueRepository, ObservationStatus, StorageError,
    StorageQuotaManager, StorageState, CLEAN_SHUTDOWN_FILE, RUNTIME_ACTIVE_FILE,
};
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

#[tokio::test]
async fn test_full_storage_lifecycle_with_coordinator() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent.db");

    let config = StorageConfig {
        db_path: db_path.clone(),
        max_storage_bytes: 524_288_000,
    };

    let engine = Arc::new(DatabaseEngine::new(&config));
    let coordinator = RuntimeCoordinator::new();
    coordinator.register_component(engine.clone()).unwrap();

    // 1. Initialize coordinator (initializes DatabaseEngine)
    coordinator.initialize().await.unwrap();
    assert_eq!(engine.state(), StorageState::Ready);
    assert_eq!(engine.health(), ComponentHealth::Healthy);

    // Verify .runtime_active exists during execution
    assert!(dir.path().join(RUNTIME_ACTIVE_FILE).exists());
    assert!(!dir.path().join(CLEAN_SHUTDOWN_FILE).exists());

    // 2. Start coordinator
    coordinator.start().await.unwrap();

    // 3. Perform write and read operations
    let obs = engine
        .with_writer(|conn| {
            ObservationQueueRepository::enqueue(
                conn,
                "SCAN_NETWORK",
                "{\"port\": 443, \"service\": \"https\"}",
                None,
            )
        })
        .await
        .unwrap();

    assert_eq!(obs.observation_type, "SCAN_NETWORK");
    assert_eq!(obs.status, ObservationStatus::Queued);

    let fetched = engine
        .with_reader(|conn| ObservationQueueRepository::fetch_queued_batch(conn, 10))
        .await
        .unwrap();

    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].id, obs.id);

    // 4. Graceful shutdown
    coordinator.shutdown().await.unwrap();
    assert_eq!(engine.state(), StorageState::Stopped);

    // Verify .clean_shutdown marker was written upon clean exit
    assert!(!dir.path().join(RUNTIME_ACTIVE_FILE).exists());
    assert!(dir.path().join(CLEAN_SHUTDOWN_FILE).exists());
}

#[tokio::test]
async fn test_concurrent_read_write_stress() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent.db");

    let config = StorageConfig {
        db_path,
        max_storage_bytes: 524_288_000,
    };

    let engine = Arc::new(DatabaseEngine::new(&config));
    netra_core::runtime::ComponentLifecycle::initialize(engine.as_ref())
        .await
        .unwrap();

    let mut handles = Vec::new();
    let num_tasks = 10;
    let iterations_per_task = 50;

    for task_idx in 0..num_tasks {
        let eng = engine.clone();
        let handle = tokio::spawn(async move {
            for i in 0..iterations_per_task {
                let payload = format!("{{\"task\": {task_idx}, \"iteration\": {i}}}");

                // Write: enqueue observation
                let enqueued = eng
                    .with_writer(move |conn| {
                        ObservationQueueRepository::enqueue(conn, "SCAN_STRESS", &payload, None)
                    })
                    .await
                    .unwrap();

                // Read: fetch queued
                let batch = eng
                    .with_reader(|conn| ObservationQueueRepository::fetch_queued_batch(conn, 5))
                    .await
                    .unwrap();

                assert!(!batch.is_empty());

                // Write: upsert finding
                let f_title = format!("Finding {task_idx}_{i}");
                eng.with_writer(move |conn| {
                    FindingsRepository::upsert(
                        conn,
                        "STRESS-001",
                        FindingSeverity::Medium,
                        &format!("target_{task_idx}"),
                        &format!("disc_{i}"),
                        &f_title,
                        "{\"evidence\": true}",
                    )
                })
                .await
                .unwrap();

                // Write: mark observation acknowledged
                let obs_id = enqueued.id.clone();
                eng.with_writer(move |conn| {
                    ObservationQueueRepository::mark_acknowledged(conn, &[obs_id])
                })
                .await
                .unwrap();
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }

    // Verify all operations committed without lock failure
    let count = engine
        .with_reader(|conn| {
            ObservationQueueRepository::count_by_status(conn, ObservationStatus::Acknowledged)
        })
        .await
        .unwrap();

    assert_eq!(count, (num_tasks * iterations_per_task) as i64);
}

#[tokio::test]
async fn test_quarantine_recovery_on_corrupt_database() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent.db");

    // Intentionally write invalid header bytes to simulate corrupt SQLite file
    fs::write(&db_path, b"NOT_A_VALID_SQLITE_HEADER_CORRUPT_BYTES").unwrap();

    let config = StorageConfig {
        db_path: db_path.clone(),
        max_storage_bytes: 524_288_000,
    };

    let engine = DatabaseEngine::new(&config);
    // Initialize should detect corruption and gracefully enter Degraded state without panic
    let init_res = netra_core::runtime::ComponentLifecycle::initialize(&engine).await;
    assert!(init_res.is_ok());

    match engine.state() {
        StorageState::Degraded(reason) => {
            assert!(reason.contains("quarantine"));
        }
        other => panic!("Expected StorageState::Degraded, got {:?}", other),
    }

    // Verify original corrupt db was moved to quarantine directory
    assert!(!db_path.exists());
    let mut found_quarantine_dir = false;
    for entry in fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("quarantine_") && entry.path().is_dir() {
            found_quarantine_dir = true;
            assert!(entry.path().join("agent.db").exists());
            assert!(entry.path().join("quarantine_meta.json").exists());
        }
    }
    assert!(found_quarantine_dir);
}

#[tokio::test]
async fn test_unclean_restart_recovers_and_initializes() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent.db");

    let config = StorageConfig {
        db_path: db_path.clone(),
        max_storage_bytes: 524_288_000,
    };

    // 1. First run: clean initialization and graceful shutdown
    {
        let engine = DatabaseEngine::new(&config);
        netra_core::runtime::ComponentLifecycle::initialize(&engine)
            .await
            .unwrap();
        netra_core::runtime::ComponentLifecycle::stop(&engine)
            .await
            .unwrap();
    }
    assert!(dir.path().join(CLEAN_SHUTDOWN_FILE).exists());

    // 2. Simulate unclean crash: delete .clean_shutdown marker
    fs::remove_file(dir.path().join(CLEAN_SHUTDOWN_FILE)).unwrap();

    // 3. Second run: should detect unclean restart, execute Tier 2 quick_check, and start cleanly
    {
        let engine = DatabaseEngine::new(&config);
        let init_res = netra_core::runtime::ComponentLifecycle::initialize(&engine).await;
        assert!(init_res.is_ok());
        assert_eq!(engine.state(), StorageState::Ready);
    }
}
