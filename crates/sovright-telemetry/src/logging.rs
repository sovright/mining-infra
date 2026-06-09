//! Structured JSON logging configuration
//!
//! Provides logging initialization with support for both pretty-printed
//! and JSON output formats, configurable via environment or explicit settings.

use std::str::FromStr;

use tracing_subscriber::{
    EnvFilter,
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

/// Log output format
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable pretty-printed format (default)
    #[default]
    Pretty,
    /// Structured JSON format for machine consumption
    Json,
}

impl FromStr for LogFormat {
    type Err = std::convert::Infallible;

    /// Parse log format from string
    ///
    /// Accepts "json", "JSON", "pretty", "Pretty", etc.
    /// Returns `Pretty` for any unrecognized value.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "json" => LogFormat::Json,
            _ => LogFormat::Pretty,
        })
    }
}

/// Initialize the logging subsystem
///
/// Sets up tracing with the specified format and default log level.
/// The log level can be overridden via the `RUST_LOG` environment variable.
///
/// # Process-global state
///
/// This function and [`init_tracing`](crate::init_tracing) both call
/// `tracing_subscriber::registry().try_init()`, which sets the global default
/// subscriber. Only one subscriber may be installed per process. If another
/// test or application path has already initialized tracing, this function
/// leaves that subscriber in place.
///
/// # Arguments
///
/// * `format` - Output format (Pretty or Json)
/// * `default_level` - Default log level filter (e.g., "info", "debug", "warn")
///
/// # Example
///
/// ```no_run
/// use sovright_telemetry::{init_logging, LogFormat};
///
/// // Initialize with pretty format and info level
/// init_logging(LogFormat::Pretty, "info");
///
/// // Or with JSON for production
/// // init_logging(LogFormat::Json, "info");
/// ```
pub fn init_logging(format: LogFormat, default_level: &str) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    match format {
        LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .with_target(true)
                        .with_thread_ids(false)
                        .with_span_events(FmtSpan::CLOSE),
                )
                .try_init()
                .ok();
        }
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .json()
                        .with_target(true)
                        .with_span_events(FmtSpan::CLOSE),
                )
                .try_init()
                .ok();
        }
    }
}

/// Initialize logging with environment-based configuration
///
/// Reads configuration from environment variables:
/// - `LOG_FORMAT`: "json" or "pretty" (default: "pretty")
/// - `RUST_LOG`: Log level filter (default: "info")
///
/// # Example
///
/// ```no_run
/// use sovright_telemetry::logging::init_logging_from_env;
///
/// init_logging_from_env();
/// ```
pub fn init_logging_from_env() {
    let format = std::env::var("LOG_FORMAT")
        .map(|s| s.parse::<LogFormat>().unwrap_or_default())
        .unwrap_or_default();

    let default_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

    init_logging(format, &default_level);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_format_from_str() {
        assert_eq!("json".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert_eq!("JSON".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert_eq!("Json".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert_eq!("pretty".parse::<LogFormat>().unwrap(), LogFormat::Pretty);
        assert_eq!("Pretty".parse::<LogFormat>().unwrap(), LogFormat::Pretty);
        assert_eq!("unknown".parse::<LogFormat>().unwrap(), LogFormat::Pretty);
        assert_eq!("".parse::<LogFormat>().unwrap(), LogFormat::Pretty);
    }

    #[test]
    fn test_log_format_default() {
        assert_eq!(LogFormat::default(), LogFormat::Pretty);
    }

    #[test]
    fn test_log_format_debug() {
        assert_eq!(format!("{:?}", LogFormat::Pretty), "Pretty");
        assert_eq!(format!("{:?}", LogFormat::Json), "Json");
    }

    #[test]
    fn test_log_format_clone() {
        let format = LogFormat::Json;
        let cloned = format;
        assert_eq!(format, cloned);
    }

    #[test]
    fn init_logging_is_idempotent() {
        init_logging(LogFormat::Pretty, "info");
        init_logging(LogFormat::Json, "debug");
    }
}
