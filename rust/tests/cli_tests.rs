use netra_core::config::NetraConfig;
use netra_core::id::{DeviceId, TenantId};
use netra_platform::detect_platform_info;

#[test]
fn test_core_identifiers_integration() {
    let dev_id = DeviceId::new();
    let ten_id = TenantId::new();

    assert!(dev_id.as_str().starts_with("dev_"));
    assert!(ten_id.as_str().starts_with("ten_"));

    let dev_str = dev_id.to_string();
    let parsed_dev = DeviceId::parse_str(&dev_str).unwrap();
    assert_eq!(dev_id, parsed_dev);
}

#[test]
fn test_platform_info_integration() {
    let info = detect_platform_info();
    assert!(!info.hostname.is_empty());
    assert!(!info.arch.is_empty());
}

#[test]
fn test_default_config_integration() {
    let mut config = NetraConfig::default();
    assert!(config.validate().is_ok());

    config.logging.level = "debug".to_string();
    assert!(config.validate().is_ok());
}
