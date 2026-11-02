//! Relay node and client implementations
//!
//! Provides async networking for FIBRE-style block relay.

mod arrival;
mod bound_raw;
mod client;
mod forwarding;
#[cfg(feature = "handled-log")]
mod handled_log;
mod metrics;
mod node;
mod ratelimit;

pub use arrival::{ArrivalSink, ReceiptObject};
pub use bound_raw::{
    BOUND_SEND_BURST_DELAY, BOUND_SEND_BURST_PACKETS, BoundArrivals, BoundBlock,
    BoundForwardConfig, BoundHandoffs, BoundIngress, BoundNodeUsage, BoundProbe, BoundProgress,
    BoundRawConfig, BoundUsed, MAX_BODY_BYTES, RELEASE_LEFTOVER, SEGMENT_BYTES, body_frames,
    bound_raw_refused, bound_raw_switch, frame_rules, is_bound, sealed_body, sealed_frame,
};
pub use client::{BlockReceiver, BlockSender, BoundSend, RelayClient, RelayPayload, SendReport};
pub use metrics::{MetricsSnapshot, RelayMetrics, render_prometheus_text};
pub use node::RelayNode;
