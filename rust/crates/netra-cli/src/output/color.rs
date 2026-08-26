//! # ANSI Terminal Colorizer (`netra-cli::output::color`)
//!
//! Provides zero-dependency ANSI color sequences conditioned on interactive TTY detection,
//! the `--no-color` CLI flag, and the standard `NO_COLOR` environment variable.

use std::io::{self, IsTerminal};

/// Terminal styling helper.
#[derive(Debug, Clone)]
pub struct Colorizer {
    enabled: bool,
}

impl Colorizer {
    /// Creates a new Colorizer inspecting stream TTY and suppression flags.
    pub fn new(is_tty: bool, no_color_flag: bool) -> Self {
        let env_no_color = std::env::var("NO_COLOR")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let enabled = is_tty && !no_color_flag && !env_no_color;
        Self { enabled }
    }

    /// Evaluates current stdout TTY status.
    pub fn for_stdout(no_color_flag: bool) -> Self {
        Self::new(io::stdout().is_terminal(), no_color_flag)
    }

    /// Evaluates current stderr TTY status.
    pub fn for_stderr(no_color_flag: bool) -> Self {
        Self::new(io::stderr().is_terminal(), no_color_flag)
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn red(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[31m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn green(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[32m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn yellow(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[33m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn cyan(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[36m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn bold(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[1m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn dim(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[2m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
}
