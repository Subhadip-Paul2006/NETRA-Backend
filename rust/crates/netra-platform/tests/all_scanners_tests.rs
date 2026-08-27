use netra_core::id::DeviceId;
use netra_platform::scanners::*;

#[tokio::test]
async fn test_all_platform_scanners_native_execution() {
    let device_id = DeviceId::new();
    let scanners = create_all_platform_scanners(false);
    assert_eq!(scanners.len(), 7);

    for scanner in scanners {
        let obs = scanner.scan(&device_id).await.unwrap();
        assert_eq!(obs.schema_version, 1);
        assert_eq!(obs.device_id, device_id);
        assert_eq!(obs.observation_type, scanner.domain());
        assert_eq!(obs.evidence_hash.len(), 64);
        assert!(
            obs.duration_ms < 5000,
            "Scanner {} exceeded 5s timeout",
            scanner.scanner_id()
        );
    }
}
