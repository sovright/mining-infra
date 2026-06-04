//! Observability for Sovright mining infrastructure
//!
//! Provides:
//! - Prometheus metrics endpoint
//! - Structured JSON logging
//! - OpenTelemetry distributed tracing

pub mod logging;
pub mod metrics;
pub mod tracing_setup;

pub use logging::{LogFormat, init_logging};
pub use metrics::{PoolMetrics, start_metrics_server};
pub use tracing_setup::{TracingConfig, TracingError, init_tracing, shutdown_tracing};
