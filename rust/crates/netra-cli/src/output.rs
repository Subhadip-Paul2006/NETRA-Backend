use serde::Serialize;
use serde_json::json;

use netra_core::error::NetraError;

/// Output controller managing stream separation (stdout for data, stderr for human UI).
pub struct OutputPresenter {
    pub json_mode: bool,
    pub quiet: bool,
}

impl OutputPresenter {
    pub fn new(json_mode: bool, quiet: bool) -> Self {
        Self { json_mode, quiet }
    }

    /// Emits structured success data according to active mode.
    pub fn emit_success<T: Serialize>(&self, command: &str, data: T, human_summary: &str) {
        if self.json_mode {
            let envelope = json!({
                "version": "1.0.0-foundation",
                "command": command,
                "status": "success",
                "data": data,
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
        } else {
            if !self.quiet {
                eprintln!("{}", human_summary);
            }
        }
    }

    /// Emits structured error according to active mode.
    pub fn emit_error(&self, command: &str, error: &NetraError) {
        if self.json_mode {
            let envelope = json!({
                "version": "1.0.0-foundation",
                "command": command,
                "status": "error",
                "error": {
                    "code": error.code(),
                    "message": error.message(),
                    "context": error.safe_context()
                },
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
        } else {
            eprintln!("✖ Error: {}", error);
        }
    }

    /// Emits informational banner to stderr if not quiet.
    pub fn banner(&self, text: &str) {
        if !self.json_mode && !self.quiet {
            eprintln!("{}", text);
        }
    }
}
