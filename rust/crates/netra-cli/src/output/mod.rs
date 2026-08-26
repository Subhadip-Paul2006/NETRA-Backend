//! # Presentation Layer & Output Engine (`netra-cli::output`)
//!
//! Enforces the Unix philosophy of canonical stream separation:
//! - `stdout`: Exclusively reserved for primary command result data (formatted human text or pure JSON).
//! - `stderr`: Dedicated to human diagnostic output, progress spinners, step updates, warnings, and error banners.

pub mod color;
pub mod envelope;
pub mod formatting;

use serde::Serialize;
use std::io::{self, Write};

use crate::errors::CliError;
use color::Colorizer;
use envelope::{JsonErrorEnvelope, JsonSuccessEnvelope};

/// Central output controller managing stream routing, formatting, and suppression.
pub struct OutputPresenter {
    pub json_mode: bool,
    pub quiet: bool,
    pub no_color: bool,
    pub color_stdout: Colorizer,
    pub color_stderr: Colorizer,
}

impl OutputPresenter {
    /// Creates a new OutputPresenter with the specified global CLI flags.
    pub fn new(json_mode: bool, quiet: bool, no_color: bool) -> Self {
        let color_stdout = Colorizer::for_stdout(no_color || json_mode);
        let color_stderr = Colorizer::for_stderr(no_color);

        Self {
            json_mode,
            quiet,
            no_color,
            color_stdout,
            color_stderr,
        }
    }

    /// Emits successful command result to `stdout`.
    ///
    /// In JSON mode (`--json`), serializes `data` inside `JsonSuccessEnvelope` without ANSI styling.
    /// In Human mode, executes `human_formatter` and prints to `stdout`.
    pub fn emit_result<T: Serialize>(
        &self,
        command: &str,
        data: &T,
        human_formatter: impl FnOnce(&Colorizer) -> String,
    ) {
        if self.json_mode {
            let envelope = JsonSuccessEnvelope::new(command, data);
            let json_str = serde_json::to_string_pretty(&envelope).unwrap_or_else(|e| {
                format!("{{\"schema_version\":\"1.0\",\"status\":\"error\",\"error\":{{\"code\":\"ERR_SERIALIZE\",\"message\":\"{e}\"}}}}")
            });
            let mut out = io::stdout().lock();
            let _ = writeln!(out, "{json_str}");
            let _ = out.flush();
        } else {
            let text = human_formatter(&self.color_stdout);
            let mut out = io::stdout().lock();
            let _ = writeln!(out, "{text}");
            let _ = out.flush();
        }
    }

    /// Emits a structured error.
    ///
    /// In JSON mode, writes `JsonErrorEnvelope` directly to `stdout` so callers can parse it.
    /// In Human mode, writes the formatted error banner to `stderr`.
    pub fn emit_error(&self, command: &str, err: &CliError) {
        if self.json_mode {
            let envelope =
                JsonErrorEnvelope::new(command, &err.code, &err.message, err.context.as_ref());
            let json_str = serde_json::to_string_pretty(&envelope).unwrap_or_else(|e| {
                format!("{{\"schema_version\":\"1.0\",\"status\":\"error\",\"error\":{{\"code\":\"ERR_SERIALIZE\",\"message\":\"{e}\"}}}}")
            });
            let mut out = io::stdout().lock();
            let _ = writeln!(out, "{json_str}");
            let _ = out.flush();
        } else {
            let mut err_out = io::stderr().lock();
            let _ = writeln!(
                err_out,
                "{} Error: {} ({})",
                self.color_stderr.red("✖"),
                err.message,
                self.color_stderr.dim(&err.code)
            );
            if let Some(ctx) = &err.context {
                let _ = writeln!(err_out, "  {} {}", self.color_stderr.dim("Context:"), ctx);
            }
            let _ = err_out.flush();
        }
    }

    /// Emits an informational banner to `stderr` (suppressed by `--quiet` or `--json`).
    pub fn banner(&self, text: &str) {
        if !self.json_mode && !self.quiet {
            let mut err_out = io::stderr().lock();
            let _ = writeln!(err_out, "{text}");
            let _ = err_out.flush();
        }
    }

    /// Emits a warning to `stderr` (preserved under `--quiet`, suppressed under `--json`).
    pub fn warn(&self, text: &str) {
        if !self.json_mode {
            let mut err_out = io::stderr().lock();
            let _ = writeln!(err_out, "{} Warning: {text}", self.color_stderr.yellow("▲"));
            let _ = err_out.flush();
        }
    }
}
