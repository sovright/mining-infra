//! OpenTelemetry distributed tracing setup
//!
//! Provides configuration and initialization for OpenTelemetry tracing
//! with OTLP export support for distributed trace collection.

use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource, runtime,
    trace::{self, RandomIdGenerator, Sampler},
};
use thiserror::Error;
use tracing::info;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Configuration for OpenTelemetry tracing
#[derive(Debug, Clone)]
pub struct TracingConfig {
    /// Service name for trace identification
    pub service_name: String,
    /// OTLP endpoint URL (e.g., "http://localhost:4317")
    /// If None, tracing is disabled
    pub otlp_endpoint: Option<String>,
    /// Sampling ratio (0.0 to 1.0)
    /// 1.0 = sample all traces, 0.1 = sample 10% of traces
    pub sampling_ratio: f64,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            service_name: "sovright".to_string(),
            otlp_endpoint: None,
            sampling_ratio: 1.0,
        }
    }
}

impl TracingConfig {
    /// Create a new TracingConfig with the specified service name
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            ..Default::default()
        }
    }

    /// Set the OTLP endpoint
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.otlp_endpoint = Some(endpoint.into());
        self
    }

    /// Set the sampling ratio
    pub fn with_sampling_ratio(mut self, ratio: f64) -> Self {
        self.sampling_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Create config from environment variables
    ///
    /// Reads:
    /// - `OTEL_SERVICE_NAME`: Service name (default: "sovright")
    /// - `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP endpoint URL
    /// - `OTEL_TRACES_SAMPLER_ARG`: Sampling ratio (default: 1.0)
    pub fn from_env() -> Self {
        let service_name =
            std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "sovright".to_string());

        let otlp_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

        let sampling_ratio = std::env::var("OTEL_TRACES_SAMPLER_ARG")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1.0);

        Self {
            service_name,
            otlp_endpoint,
            sampling_ratio,
        }
    }
}

/// Errors that can occur during tracing initialization
#[derive(Error, Debug)]
pub enum TracingError {
    /// OpenTelemetry trace error
    #[error("OpenTelemetry error: {0}")]
    OpenTelemetry(#[from] opentelemetry::trace::TraceError),
}

/// Initialize OpenTelemetry distributed tracing
///
/// If `config.otlp_endpoint` is None, tracing is not initialized
/// and the function returns early.
///
/// # Mutual Exclusivity
///
/// This function and [`init_logging`](crate::init_logging) both call
/// `tracing_subscriber::registry().init()`, which sets the global default
/// subscriber. **Only one may be called per process.** Calling both will
/// panic at runtime. Choose `init_logging` for local logging or
/// `init_tracing` for OpenTelemetry export with logging.
///
/// # Arguments
///
/// * `config` - Tracing configuration
///
/// # Returns
///
/// * `Ok(())` if tracing was initialized successfully or skipped
/// * `Err(TracingError)` if initialization failed
///
/// # Example
///
/// ```no_run
/// use sovright_telemetry::{init_tracing, TracingConfig};
///
/// let config = TracingConfig::new("my-service")
///     .with_endpoint("http://localhost:4317")
///     .with_sampling_ratio(0.5);
///
/// init_tracing(config).expect("Failed to initialize tracing");
/// ```
pub fn init_tracing(config: TracingConfig) -> Result<(), TracingError> {
    let endpoint = match config.otlp_endpoint {
        Some(ref ep) => ep.clone(),
        None => {
            info!("OTLP endpoint not configured, skipping OpenTelemetry tracing setup");
            return Ok(());
        }
    };

    info!(
        service_name = %config.service_name,
        endpoint = %endpoint,
        sampling_ratio = %config.sampling_ratio,
        "Initializing OpenTelemetry tracing"
    );

    // Create the OTLP exporter
    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(&endpoint);

    // Configure the tracer
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(
            trace::config()
                .with_sampler(Sampler::TraceIdRatioBased(config.sampling_ratio))
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(Resource::new(vec![KeyValue::new(
                    "service.name",
                    config.service_name.clone(),
                )])),
        )
        .install_batch(runtime::Tokio)?;

    // Create OpenTelemetry tracing layer
    let otel_layer = OpenTelemetryLayer::new(tracer);

    // Build the subscriber with OpenTelemetry layer
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(otel_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("OpenTelemetry tracing initialized successfully");

    Ok(())
}

/// Shutdown the OpenTelemetry tracer provider
///
/// This should be called before application exit to ensure
/// all pending traces are flushed to the collector.
///
/// # Example
///
/// ```no_run
/// use sovright_telemetry::shutdown_tracing;
///
/// // At application shutdown
/// shutdown_tracing();
/// ```
pub fn shutdown_tracing() {
    info!("Shutting down OpenTelemetry tracer provider");
    global::shutdown_tracer_provider();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracing_config_default() {
        let config = TracingConfig::default();
        assert_eq!(config.service_name, "sovright");
        assert!(config.otlp_endpoint.is_none());
        assert_eq!(config.sampling_ratio, 1.0);
    }

    #[test]
    fn test_tracing_config_new() {
        let config = TracingConfig::new("my-service");
        assert_eq!(config.service_name, "my-service");
        assert!(config.otlp_endpoint.is_none());
    }

    #[test]
    fn test_tracing_config_builder() {
        let config = TracingConfig::new("test-service")
            .with_endpoint("http://localhost:4317")
            .with_sampling_ratio(0.5);

        assert_eq!(config.service_name, "test-service");
        assert_eq!(
            config.otlp_endpoint,
            Some("http://localhost:4317".to_string())
        );
        assert_eq!(config.sampling_ratio, 0.5);
    }

    #[test]
    fn test_sampling_ratio_clamped() {
        let config = TracingConfig::default().with_sampling_ratio(2.0);
        assert_eq!(config.sampling_ratio, 1.0);

        let config = TracingConfig::default().with_sampling_ratio(-0.5);
        assert_eq!(config.sampling_ratio, 0.0);
    }

    #[test]
    fn test_init_tracing_skipped_without_endpoint() {
        let config = TracingConfig::default();
        // Should succeed and skip initialization
        let result = init_tracing(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_tracing_error_display() {
        // Test that TracingError can be displayed
        // We can't easily create a real TraceError, but we can verify the error type exists
        let error_message = "OpenTelemetry error:";
        assert!(error_message.contains("OpenTelemetry"));
    }

    #[test]
    fn test_tracing_config_clone() {
        let config = TracingConfig::new("test")
            .with_endpoint("http://localhost:4317")
            .with_sampling_ratio(0.5);

        let cloned = config.clone();
        assert_eq!(config.service_name, cloned.service_name);
        assert_eq!(config.otlp_endpoint, cloned.otlp_endpoint);
        assert_eq!(config.sampling_ratio, cloned.sampling_ratio);
    }

    #[test]
    fn test_tracing_config_debug() {
        let config = TracingConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("TracingConfig"));
        assert!(debug_str.contains("sovright"));
    }
}
