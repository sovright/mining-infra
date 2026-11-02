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
    ANCHOR_HEADER_WINDOW, BOUND_HELLO, BOUND_HELLO_ACK, BOUND_RELEASE, BOUND_SEND_BURST_DELAY,
    BOUND_SEND_BURST_PACKETS, BoundArrivals, BoundBlock, BoundForwardConfig, BoundHandoffs,
    BoundIngress, BoundNodeUsage, BoundProbe, BoundProgress, BoundRawConfig, BoundUsed,
    HELLO_RECEIVES, MAX_BODIES_PER_KEY_PER_BLOCK, MAX_BODY_BYTES, NODE_ASSEMBLY_TTL,
    RELEASE_LEFTOVER, SEGMENT_BYTES, body_frames, bound_hello, bound_raw_refused, bound_raw_switch,
    bound_release, frame_rules, is_bound, sealed_body, sealed_frame,
};
pub use client::{
    BOUND_ACK_TTL, BOUND_HELLO_WAIT, BlockReceiver, BlockSender, BoundSend, RelayClient,
    RelayPayload, SHARED_EGRESS_BURST, SendReport,
};
pub use metrics::{
    MetricsSnapshot, RelayMetrics, render_bound_prometheus_text, render_prometheus_text,
};
pub use node::RelayNode;
