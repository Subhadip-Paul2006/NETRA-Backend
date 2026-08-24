use std::process::ExitCode as StdExitCode;

/// Standard exit codes for NETRA CLI executions according to specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ExitCode {
    /// Command completed successfully without policy violations.
    Success = 0,
    /// Operational or system error (network unreachable, permission denied).
    OperationalError = 1,
    /// Security audit failed policy threshold (--fail-on).
    PolicyFailure = 2,
    /// Invalid arguments or bad CLI syntax.
    InvalidArguments = 3,
}

impl ExitCode {
    pub fn as_i32(&self) -> i32 {
        *self as i32
    }
}

impl From<ExitCode> for StdExitCode {
    fn from(code: ExitCode) -> Self {
        StdExitCode::from(code.as_i32() as u8)
    }
}
