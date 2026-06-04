//! Observability for Sovright mining infrastructure
//!
//! Provides:
//! - Prometheus metrics endpoint
//! - Structured JSON logging
//! - OpenTelemetry distributed tracing

pub mod logging;
pub mod metrics;
pub mod tracing_setup;

pub use logging::{init_logging, LogFormat};
pub use metrics::{start_metrics_server, PoolMetrics};
pub use tracing_setup::{init_tracing, shutdown_tracing, TracingConfig, TracingError};
