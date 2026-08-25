//! Integration tests verifying platform process isolation handlers.

use netra_platform::create_process_isolation;

#[test]
fn test_create_process_isolation_handler() {
    let limit_bytes = 100 * 1024 * 1024; // 100 MB
    let isolation =
        create_process_isolation(limit_bytes).expect("failed to create isolation handler");

    assert_eq!(isolation.memory_limit_bytes(), limit_bytes);
    assert!(!isolation.name().is_empty());
}
