//! # CLI Output Formatting & Stream Purity Tests (`output_tests.rs`)

use netra_cli::output::color::Colorizer;
use netra_cli::output::envelope::{JsonErrorEnvelope, JsonSuccessEnvelope};
use netra_cli::version::{NETRA_VERSION, SCHEMA_VERSION};
use serde_json::Value;

#[test]
fn test_json_success_envelope_contract() {
    let dummy_data = serde_json::json!({
        "total_size_bytes": 1048576,
        "wal_size_bytes": 32768,
        "saturation_percent": 0.20,
    });

    let envelope = JsonSuccessEnvelope::new("storage status", &dummy_data);
    let json_str = serde_json::to_string_pretty(&envelope).unwrap();

    let parsed: Value = serde_json::from_str(&json_str).expect("Must be valid JSON");

    assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    assert_eq!(parsed["netra_version"], NETRA_VERSION);
    assert_eq!(parsed["command"], "storage status");
    assert_eq!(parsed["status"], "success");
    assert_eq!(parsed["data"]["total_size_bytes"], 1048576);
    assert_eq!(parsed["data"]["wal_size_bytes"], 32768);
    assert!(parsed["timestamp"].is_string());
}

#[test]
fn test_json_error_envelope_contract() {
    let context_val = serde_json::json!({ "tier": 2, "db_path": "tmp/agent.db" });
    let envelope = JsonErrorEnvelope::new(
        "storage check",
        "ERR_STORAGE_CORRUPTION",
        "PRAGMA quick_check failed",
        Some(&context_val),
    );

    let json_str = serde_json::to_string_pretty(&envelope).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).expect("Must be valid JSON");

    assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    assert_eq!(parsed["netra_version"], NETRA_VERSION);
    assert_eq!(parsed["command"], "storage check");
    assert_eq!(parsed["status"], "error");
    assert_eq!(parsed["error"]["code"], "ERR_STORAGE_CORRUPTION");
    assert_eq!(parsed["error"]["message"], "PRAGMA quick_check failed");
    assert_eq!(parsed["error"]["context"]["tier"], 2);
    assert!(parsed["timestamp"].is_string());
}

#[test]
fn test_colorizer_behavior() {
    let enabled_color = Colorizer::new(true, false);
    let disabled_color = Colorizer::new(false, false);
    let no_color_flag = Colorizer::new(true, true);

    let raw = "NETRA Status";
    let formatted_enabled = enabled_color.green(raw);
    let formatted_disabled = disabled_color.green(raw);
    let formatted_flag = no_color_flag.green(raw);

    assert!(formatted_enabled.contains("\x1b[32m"));
    assert_eq!(formatted_disabled, raw);
    assert_eq!(formatted_flag, raw);
}
