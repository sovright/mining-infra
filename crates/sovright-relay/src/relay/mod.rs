//! Relay node and client implementations
//!
//! Provides async networking for FIBRE-style block relay.

mod arrival;
mod bound_raw;
mod client;
mod forwarding;
mod metrics;
mod node;
mod ratelimit;

pub use arrival::{ArrivalSink, ReceiptObject};
pub use bound_raw::{
    BoundBlock, BoundForwardConfig, BoundNodeUsage, BoundProbe, BoundRawConfig, BoundUsed,
    MAX_BODY_BYTES, SEGMENT_BYTES, body_frames, frame_rules, is_bound, sealed_body, sealed_frame,
};
pub use client::{BlockReceiver, BlockSender, RelayClient, RelayPayload};
pub use metrics::{MetricsSnapshot, RelayMetrics, render_prometheus_text};
pub use node::RelayNode;
