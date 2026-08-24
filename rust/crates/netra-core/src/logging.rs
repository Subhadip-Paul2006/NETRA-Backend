use std::sync::Once;

use tracing_subscriber::{filter::EnvFilter, fmt, prelude::*};

use crate::config::LogConfig;
use crate::error::{NetraError, Result};

static INIT_LOGGER: Once = Once::new();

/// Initializes structured logging subsystem based on LogConfig.
/// Safe to call multiple times (subsequent invocations are no-ops).
pub fn init_logging(config: &LogConfig) -> Result<()> {
    let mut init_result = Ok(());

    INIT_LOGGER.call_once(|| {
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.level));

        if config.format.eq_ignore_ascii_case("json") {
            let json_layer = fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true)
                .with_target(true);

            if let Err(e) = tracing_subscriber::registry()
                .with(env_filter)
                .with(json_layer)
                .try_init()
            {
                init_result = Err(NetraError::internal(format!(
                    "Failed to initialize JSON tracing subscriber: {e}"
                )));
            }
        } else {
            let human_layer = fmt::layer()
                .with_ansi(!config.no_color)
                .with_target(false)
                .with_level(true);

            if let Err(e) = tracing_subscriber::registry()
                .with(env_filter)
                .with(human_layer)
                .try_init()
            {
                init_result = Err(NetraError::internal(format!(
                    "Failed to initialize human tracing subscriber: {e}"
                )));
            }
        }
    });

    init_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logging_init_idempotent() {
        let config = LogConfig::default();
        assert!(init_logging(&config).is_ok());
        assert!(init_logging(&config).is_ok());
    }
}
