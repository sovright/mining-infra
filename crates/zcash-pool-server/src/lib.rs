//! Zcash Pool Server for Stratum V2
//!
//! This crate provides a basic pool server that:
//! - Accepts miner connections over TCP
//! - Distributes Equihash mining jobs
//! - Validates submitted shares
//! - Tracks contributions for PPS payout
//! - Supports Job Declaration (JD) protocol for Coinbase-Only mining
//!
//! ## Security Features
//!
//! - Automatic reconnection with exponential backoff (EROSION mitigation)
//! - Application-layer sequence validation (replay protection)
//! - Short-lived connection detection (attack indicators)
//! - Security metrics for monitoring

pub mod channel;
pub mod config;
pub mod duplicate;
pub mod error;
#[cfg(feature = "relay")]
pub mod relay;
pub mod job;
pub mod payout;
pub mod ratelimit;
pub mod reconnect;
pub mod security;
pub mod server;
pub mod session;
pub mod share;

pub use channel::{Channel, ChannelJob};
pub use config::PoolConfig;
pub use duplicate::{DuplicateDetector, InMemoryDuplicateDetector};
pub use error::PoolError;
#[cfg(feature = "relay")]
pub use relay::RelayHandle;
pub use job::JobDistributor;
pub use payout::{MinerId, MinerStats, PayoutTracker};
pub use ratelimit::{RateLimitResult, RateLimiter};
pub use reconnect::{DisconnectReason, FailureStats, ReconnectConfig, ReconnectManager};
pub use security::{
    ConnectionStats, ConnectionTracker, SecurityMetrics, SecurityMetricsSnapshot,
    SequenceCheckResult, SequenceValidator, TimingJitter,
};
pub use server::{PoolServer, PoolStats};
pub use session::{ServerMessage, Session, SessionMessage};
pub use share::{ShareProcessor, ShareValidationResult};

// Re-export JD Server types for convenient access
pub use zcash_jd_server::{handle_jd_client, JdServer, JdServerConfig};
