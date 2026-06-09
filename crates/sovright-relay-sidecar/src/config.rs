//! Configuration file support

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Error type alias for config operations
type ConfigError = Box<dyn std::error::Error + Send + Sync>;

/// Configuration loaded from file
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Zebra RPC URL
    #[serde(default = "default_zebra_url")]
    pub zebra_url: String,

    /// Relay peer addresses
    pub relay_peers: Vec<String>,

    /// Authentication key (hex)
    pub auth_key: Option<String>,

    /// Local bind address
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// Number of FEC data shards for relay traffic.
    #[serde(default = "default_data_shards")]
    pub data_shards: usize,

    /// Number of FEC parity shards for relay traffic.
    #[serde(default = "default_parity_shards")]
    pub parity_shards: usize,

    /// Poll interval in milliseconds
    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,

    /// Announce local Zebra templates into the relay network.
    #[serde(default = "default_announce_templates")]
    pub announce_templates: bool,

    /// Receive relay-reconstructed compact blocks from the relay network.
    #[serde(default)]
    pub receive_relay_blocks: bool,

    /// Submit eligible relay-received blocks to Zebra.
    #[serde(default)]
    pub enable_submitblock: bool,

    /// Reconstruct short-id compact blocks using the sidecar mempool.
    #[serde(default)]
    pub compact_reconstruction_enabled: bool,

    /// Maintain a sidecar-local transaction cache for compact reconstruction.
    #[serde(default)]
    pub tx_cache_enabled: bool,

    /// Optional local TCP bind address for transaction-feed ingestion.
    #[serde(default)]
    pub tx_feed_bind_addr: Option<String>,

    /// Maximum transactions to keep in the sidecar transaction cache.
    #[serde(default = "default_tx_cache_max_entries")]
    pub tx_cache_max_entries: usize,

    /// Maximum total transaction bytes to keep in the sidecar transaction cache.
    #[serde(default = "default_tx_cache_max_bytes")]
    pub tx_cache_max_bytes: usize,

    /// Maximum individual transaction payload size to accept into the cache.
    #[serde(default = "default_tx_cache_max_tx_bytes")]
    pub tx_cache_max_tx_bytes: usize,

    /// Maximum incomplete raw blocks to buffer while waiting for segments.
    #[serde(default = "default_raw_segment_max_incomplete_blocks")]
    pub raw_segment_max_incomplete_blocks: usize,

    /// Maximum total raw segment payload bytes to hold in memory.
    #[serde(default = "default_raw_segment_max_payload_bytes")]
    pub raw_segment_max_payload_bytes: usize,

    /// Maximum age for an incomplete raw block segment set.
    #[serde(default = "default_raw_segment_ttl_secs")]
    pub raw_segment_ttl_secs: u64,

    /// Number of outbound relay packets to send before applying
    /// `send_burst_delay_micros`. Zero disables client-side pacing.
    #[serde(default)]
    pub send_burst_packets: usize,

    /// Optional client-side delay after each outbound relay packet burst.
    #[serde(default)]
    pub send_burst_delay_micros: u64,

    /// Optional Prometheus textfile path for sidecar receive metrics.
    #[serde(default)]
    pub metrics_textfile: Option<PathBuf>,

    /// Configuration for the relay-received submit safety gate.
    ///
    /// The gate sits in front of `submit_block` once `enable_submitblock` is on.
    /// It is configured separately from `enable_submitblock` so the
    /// production cutover can land the gate in `enabled = true` mode while
    /// `enable_submitblock` is still false, exercising the decision logic on
    /// every reassembled candidate without forwarding anything upstream.
    #[serde(default)]
    pub submit_gate: SubmitGateConfig,
}

/// Configuration for the safety gate in front of `submit_block`.
///
/// All fields default to safe values that match the gate defaults. The
/// `enabled` flag defaults to false so the gate is explicitly opt-in.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct SubmitGateConfig {
    /// Master switch. Default false. The gate must be explicitly enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Allowed block heights below the local tip. Default 3.
    #[serde(default = "default_submit_gate_allowed_below")]
    pub allowed_below: u64,
    /// Dedup window in seconds. Default 300 (5 minutes).
    #[serde(default = "default_submit_gate_dedup_window_secs")]
    pub dedup_window_secs: u64,
    /// Maximum entries to retain in the dedup ring. Default 256.
    #[serde(default = "default_submit_gate_dedup_capacity")]
    pub dedup_capacity: usize,
}

impl Default for SubmitGateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_below: default_submit_gate_allowed_below(),
            dedup_window_secs: default_submit_gate_dedup_window_secs(),
            dedup_capacity: default_submit_gate_dedup_capacity(),
        }
    }
}

impl SubmitGateConfig {
    /// Convert to the gate's runtime config struct.
    pub fn to_gate_config(&self) -> crate::submit_gate::GateConfig {
        crate::submit_gate::GateConfig {
            enabled: self.enabled,
            allowed_below: self.allowed_below,
            dedup_window: std::time::Duration::from_secs(self.dedup_window_secs),
            dedup_capacity: self.dedup_capacity,
        }
    }
}

fn default_submit_gate_allowed_below() -> u64 {
    3
}

fn default_submit_gate_dedup_window_secs() -> u64 {
    300
}

fn default_submit_gate_dedup_capacity() -> usize {
    256
}

fn default_zebra_url() -> String {
    "http://127.0.0.1:8232".to_string()
}

fn default_bind_addr() -> String {
    "0.0.0.0:0".to_string()
}

fn default_poll_interval() -> u64 {
    100
}

fn default_data_shards() -> usize {
    10
}

fn default_parity_shards() -> usize {
    3
}

fn default_announce_templates() -> bool {
    true
}

fn default_raw_segment_max_incomplete_blocks() -> usize {
    128
}

fn default_raw_segment_max_payload_bytes() -> usize {
    64 * 1024 * 1024
}

fn default_raw_segment_ttl_secs() -> u64 {
    120
}

fn default_tx_cache_max_entries() -> usize {
    50_000
}

fn default_tx_cache_max_bytes() -> usize {
    128 * 1024 * 1024
}

fn default_tx_cache_max_tx_bytes() -> usize {
    2 * 1024 * 1024
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Parse relay peers to SocketAddr
    pub fn parsed_relay_peers(&self) -> Result<Vec<SocketAddr>, ConfigError> {
        self.relay_peers
            .iter()
            .map(|s| {
                s.parse()
                    .map_err(|e| format!("invalid relay peer '{}': {}", s, e).into())
            })
            .collect()
    }

    /// Parse auth key to bytes
    pub fn parsed_auth_key(&self) -> Result<[u8; 32], ConfigError> {
        if let Some(key_hex) = &self.auth_key {
            let bytes = hex::decode(key_hex)?;
            if bytes.len() != 32 {
                return Err("auth_key must be 32 bytes".into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        } else {
            Ok([0u8; 32])
        }
    }

    /// Parse bind address
    pub fn parsed_bind_addr(&self) -> Result<SocketAddr, ConfigError> {
        Ok(self.bind_addr.parse()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config() {
        let toml = r#"
            zebra_url = "http://localhost:8232"
            relay_peers = ["192.168.1.1:8333", "192.168.1.2:8333"]
            auth_key = "0000000000000000000000000000000000000000000000000000000000000000"
            poll_interval_ms = 50
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(config.zebra_url, "http://localhost:8232");
        assert_eq!(config.relay_peers.len(), 2);
        assert_eq!(config.poll_interval_ms, 50);
    }

    #[test]
    fn config_defaults() {
        let toml = r#"
            relay_peers = ["127.0.0.1:8333"]
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(config.zebra_url, "http://127.0.0.1:8232");
        assert_eq!(config.bind_addr, "0.0.0.0:0");
        assert_eq!(config.data_shards, 10);
        assert_eq!(config.parity_shards, 3);
        assert_eq!(config.poll_interval_ms, 100);
        assert!(config.announce_templates);
        assert!(!config.receive_relay_blocks);
        assert!(!config.enable_submitblock);
        assert!(!config.compact_reconstruction_enabled);
        assert_eq!(config.raw_segment_max_incomplete_blocks, 128);
        assert_eq!(config.raw_segment_max_payload_bytes, 64 * 1024 * 1024);
        assert_eq!(config.raw_segment_ttl_secs, 120);
        assert_eq!(config.send_burst_packets, 0);
        assert_eq!(config.send_burst_delay_micros, 0);
        assert_eq!(config.metrics_textfile, None);
        assert!(!config.tx_cache_enabled);
        assert_eq!(config.tx_feed_bind_addr, None);
        assert_eq!(config.tx_cache_max_entries, 50_000);
        assert_eq!(config.tx_cache_max_bytes, 128 * 1024 * 1024);
        assert_eq!(config.tx_cache_max_tx_bytes, 2 * 1024 * 1024);
        assert!(!config.submit_gate.enabled);
        assert_eq!(config.submit_gate.allowed_below, 3);
        assert_eq!(config.submit_gate.dedup_window_secs, 300);
        assert_eq!(config.submit_gate.dedup_capacity, 256);
    }

    #[test]
    fn config_parses_submit_gate_overrides() {
        let toml = r#"
            relay_peers = ["127.0.0.1:8333"]

            [submit_gate]
            enabled = true
            allowed_below = 6
            dedup_window_secs = 600
            dedup_capacity = 1024
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert!(config.submit_gate.enabled);
        assert_eq!(config.submit_gate.allowed_below, 6);
        assert_eq!(config.submit_gate.dedup_window_secs, 600);
        assert_eq!(config.submit_gate.dedup_capacity, 1024);

        let gate = config.submit_gate.to_gate_config();
        assert!(gate.enabled);
        assert_eq!(gate.allowed_below, 6);
        assert_eq!(gate.dedup_window, std::time::Duration::from_secs(600));
        assert_eq!(gate.dedup_capacity, 1024);
    }

    #[test]
    fn config_parses_submit_safety_flags() {
        let toml = r#"
            relay_peers = ["127.0.0.1:8333"]
            announce_templates = false
            receive_relay_blocks = true
            enable_submitblock = true
            compact_reconstruction_enabled = true
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert!(!config.announce_templates);
        assert!(config.receive_relay_blocks);
        assert!(config.enable_submitblock);
        assert!(config.compact_reconstruction_enabled);
    }

    #[test]
    fn config_parses_relay_fec_profile() {
        let toml = r#"
            relay_peers = ["127.0.0.1:8333"]
            data_shards = 96
            parity_shards = 32
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(config.data_shards, 96);
        assert_eq!(config.parity_shards, 32);
    }

    #[test]
    fn config_parses_raw_segment_buffer_limits() {
        let toml = r#"
            relay_peers = ["127.0.0.1:8333"]
            raw_segment_max_incomplete_blocks = 16
            raw_segment_max_payload_bytes = 1048576
            raw_segment_ttl_secs = 30
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(config.raw_segment_max_incomplete_blocks, 16);
        assert_eq!(config.raw_segment_max_payload_bytes, 1_048_576);
        assert_eq!(config.raw_segment_ttl_secs, 30);
    }

    #[test]
    fn config_parses_send_pacing() {
        let toml = r#"
            relay_peers = ["127.0.0.1:8333"]
            send_burst_packets = 32
            send_burst_delay_micros = 1000
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(config.send_burst_packets, 32);
        assert_eq!(config.send_burst_delay_micros, 1000);
    }

    #[test]
    fn config_parses_metrics_textfile() {
        let toml = r#"
            relay_peers = ["127.0.0.1:8333"]
            metrics_textfile = "/var/lib/sovright-relay-sidecar/metrics.prom"
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(
            config.metrics_textfile,
            Some(PathBuf::from(
                "/var/lib/sovright-relay-sidecar/metrics.prom"
            ))
        );
    }

    #[test]
    fn config_parses_tx_cache_provider_settings() {
        let toml = r#"
            relay_peers = ["127.0.0.1:8333"]
            tx_cache_enabled = true
            tx_cache_max_entries = 123
            tx_cache_max_bytes = 456
            tx_cache_max_tx_bytes = 789
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert!(config.tx_cache_enabled);
        assert_eq!(config.tx_cache_max_entries, 123);
        assert_eq!(config.tx_cache_max_bytes, 456);
        assert_eq!(config.tx_cache_max_tx_bytes, 789);
    }

    #[test]
    fn config_parses_tx_feed_bind_addr() {
        let toml = r#"
            relay_peers = ["127.0.0.1:8333"]
            tx_feed_bind_addr = "127.0.0.1:19091"
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(
            config.tx_feed_bind_addr,
            Some("127.0.0.1:19091".to_string())
        );
    }
}
