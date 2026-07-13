use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{IngressError, Result};
use crate::wire::DEFAULT_PORT;

/// Known Zcash forks that reused the Zcash network magic and gossip into
/// Zcash address books, but whose blocks are not Zcash mainnet blocks.
const DENIED_PEER_PORTS: &[u16] = &[16_125, 26_125];

const DEFAULT_SUBMITBLOCK_MAX_BLOCK_BYTES: usize = 4 * 1024 * 1024;

/// Optional loopback JSON-RPC front door for pool-originated solved blocks.
///
/// The pool sends its normal `submitblock` request here. The ingress starts
/// relay fanout and local Zebra submission concurrently, then returns Zebra's
/// result. Both the listener and backend are loopback-only in v1 so this does
/// not create a new unauthenticated network service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitBlockRpcConfig {
    pub bind_addr: SocketAddr,
    pub zebra_url: String,
    pub max_block_bytes: usize,
    pub max_requests_per_minute: usize,
    pub relay_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub seeds: Vec<String>,
    pub peers: Vec<SocketAddr>,
    pub max_peers: usize,
    pub connect_timeout: Duration,
    pub peer_runtime: Duration,
    pub crawler_enabled: bool,
    pub crawler_max_known_peers: usize,
    pub crawler_max_addr_per_message: usize,
    pub crawler_drain_interval: Duration,
    pub rotation_enabled: bool,
    pub rotation_cooldown: Duration,
    pub rotation_failure_cooldown: Duration,
    pub accept_nonstandard_ports: bool,
    pub peer_scoring_enabled: bool,
    pub peer_score_block_inv: i64,
    pub peer_score_block_received: i64,
    pub peer_score_relay_forwarded: i64,
    pub peer_score_error: i64,
    pub tx_cache_enabled: bool,
    pub tx_cache_max_entries: usize,
    pub tx_cache_max_bytes: usize,
    pub tx_cache_max_tx_bytes: usize,
    pub tx_feed_addr: Option<SocketAddr>,
    pub tx_request_limit_per_inv: usize,
    pub event_log: Option<PathBuf>,
    pub relay_peers: Vec<SocketAddr>,
    pub relay_bind_addr: SocketAddr,
    pub relay_auth_key: Option<[u8; 32]>,
    pub relay_data_shards: usize,
    pub relay_parity_shards: usize,
    /// Emit adaptive (version-3) FEC chunks sized per block on the relay send
    /// path. Read from `SOVRIGHT_P2P_RELAY_ADAPTIVE_FEC` (default false). The
    /// receive path always decodes both v2 and v3, so this is safe to roll out
    /// across a mixed-version fleet.
    pub relay_adaptive_fec: bool,
    pub relay_send_burst_packets: usize,
    pub relay_send_burst_delay_micros: u64,
    pub relay_compact_from_tx_cache: bool,
    /// Send a compact *skeleton* (header + nonce + all-non-coinbase short_ids +
    /// coinbase) first and redundantly ahead of the full compact block, so a
    /// receiver that already holds the txs reconstructs before the FEC'd bodies
    /// arrive. Read from `SOVRIGHT_P2P_RELAY_SKELETON_FIRST` (default false).
    /// Only meaningful with `relay_compact_from_tx_cache`; a no-op otherwise.
    pub relay_skeleton_first: bool,
    pub relay_raw_fallback_with_tx_cache: bool,
    pub relay_raw_segment_send_rounds: usize,
    pub relay_raw_segment_round_delay_millis: u64,
    /// First-seen-wins window for the relay-bridge forward path. If the same
    /// block hash is offered to `forward_block` twice inside this window,
    /// the second call returns `ForwardMode::Deduplicated` without re-encoding
    /// or re-broadcasting. Default 30 seconds.
    pub relay_forward_dedup_window: Duration,
    /// Maximum bounded LRU size for the forward dedup ring. Default 64.
    pub relay_forward_dedup_capacity: usize,
    pub submitblock_rpc: Option<SubmitBlockRpcConfig>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let seeds = env_csv("SOVRIGHT_P2P_DNS_SEEDS").unwrap_or_else(default_seeds);
        let peers = env_socket_csv("SOVRIGHT_P2P_PEERS")?;
        let max_peers = env_usize("SOVRIGHT_P2P_MAX_PEERS", 8)?;
        let connect_timeout = Duration::from_secs(env_u64("SOVRIGHT_P2P_CONNECT_TIMEOUT_SECS", 5)?);
        let peer_runtime = Duration::from_secs(env_u64("SOVRIGHT_P2P_PEER_RUNTIME_SECS", 0)?);
        let crawler_enabled = env_bool("SOVRIGHT_P2P_CRAWLER_ENABLED", false)?;
        let crawler_max_known_peers = env_usize("SOVRIGHT_P2P_CRAWLER_MAX_KNOWN_PEERS", 5_000)?;
        let crawler_max_addr_per_message =
            env_usize("SOVRIGHT_P2P_CRAWLER_MAX_ADDR_PER_MESSAGE", 1_000)?;
        let crawler_drain_interval =
            Duration::from_secs(env_u64("SOVRIGHT_P2P_CRAWLER_DRAIN_INTERVAL_SECS", 5)?);
        let rotation_enabled = env_bool("SOVRIGHT_P2P_ROTATION_ENABLED", false)?;
        let rotation_cooldown =
            Duration::from_secs(env_u64("SOVRIGHT_P2P_ROTATION_COOLDOWN_SECS", 30)?);
        let rotation_failure_cooldown =
            Duration::from_secs(env_u64("SOVRIGHT_P2P_ROTATION_FAILURE_COOLDOWN_SECS", 120)?);
        let accept_nonstandard_ports = env_bool("SOVRIGHT_P2P_ACCEPT_NONSTANDARD_PORTS", false)?;
        let peer_scoring_enabled = env_bool("SOVRIGHT_P2P_PEER_SCORING_ENABLED", false)?;
        let peer_score_block_inv = env_i64("SOVRIGHT_P2P_PEER_SCORE_BLOCK_INV", 5)?;
        let peer_score_block_received = env_i64("SOVRIGHT_P2P_PEER_SCORE_BLOCK_RECEIVED", 25)?;
        let peer_score_relay_forwarded = env_i64("SOVRIGHT_P2P_PEER_SCORE_FORGE_FORWARDED", 10)?;
        let peer_score_error = env_i64("SOVRIGHT_P2P_PEER_SCORE_ERROR", -50)?;
        let tx_cache_enabled = env_bool("SOVRIGHT_P2P_TX_CACHE_ENABLED", false)?;
        let tx_cache_max_entries = env_usize("SOVRIGHT_P2P_TX_CACHE_MAX_ENTRIES", 200_000)?;
        let tx_cache_max_bytes = env_usize("SOVRIGHT_P2P_TX_CACHE_MAX_BYTES", 536_870_912)?;
        let tx_cache_max_tx_bytes = env_usize("SOVRIGHT_P2P_TX_CACHE_MAX_TX_BYTES", 2_097_152)?;
        let tx_feed_addr = env_optional_socket("SOVRIGHT_P2P_TX_FEED_ADDR")?;
        let tx_request_limit_per_inv = env_usize("SOVRIGHT_P2P_TX_REQUEST_LIMIT_PER_INV", 256)?;
        let event_log = env::var("SOVRIGHT_P2P_EVENT_LOG").ok().map(PathBuf::from);
        let relay_peers = env_socket_csv("SOVRIGHT_P2P_RELAY_PEERS")?;
        let relay_bind_addr = env::var("SOVRIGHT_P2P_RELAY_BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:0".to_string())
            .parse()
            .map_err(|e| {
                IngressError::Config(format!("invalid SOVRIGHT_P2P_RELAY_BIND_ADDR: {e}"))
            })?;
        let relay_auth_key = match env::var("SOVRIGHT_P2P_RELAY_AUTH_KEY_HEX") {
            Ok(value) => Some(parse_auth_key(&value)?),
            Err(_) => None,
        };
        let relay_data_shards = env_usize("SOVRIGHT_P2P_RELAY_DATA_SHARDS", 10)?;
        let relay_parity_shards = env_usize("SOVRIGHT_P2P_RELAY_PARITY_SHARDS", 3)?;
        let relay_adaptive_fec = env_bool("SOVRIGHT_P2P_RELAY_ADAPTIVE_FEC", false)?;
        let relay_send_burst_packets = env_usize("SOVRIGHT_P2P_RELAY_SEND_BURST_PACKETS", 0)?;
        let relay_send_burst_delay_micros =
            env_u64("SOVRIGHT_P2P_RELAY_SEND_BURST_DELAY_MICROS", 0)?;
        let relay_compact_from_tx_cache =
            env_bool("SOVRIGHT_P2P_RELAY_COMPACT_FROM_TX_CACHE", false)?;
        let relay_skeleton_first = env_bool("SOVRIGHT_P2P_RELAY_SKELETON_FIRST", false)?;
        let relay_raw_fallback_with_tx_cache =
            env_bool("SOVRIGHT_P2P_RELAY_RAW_FALLBACK_WITH_TX_CACHE", false)?;
        let relay_raw_segment_send_rounds =
            env_usize("SOVRIGHT_P2P_RELAY_RAW_SEGMENT_SEND_ROUNDS", 1)?;
        if relay_raw_segment_send_rounds == 0 {
            return Err(IngressError::Config(
                "SOVRIGHT_P2P_RELAY_RAW_SEGMENT_SEND_ROUNDS must be at least 1".to_string(),
            ));
        }
        let relay_raw_segment_round_delay_millis =
            env_u64("SOVRIGHT_P2P_RELAY_RAW_SEGMENT_ROUND_DELAY_MILLIS", 0)?;
        let relay_forward_dedup_window =
            Duration::from_secs(env_u64("SOVRIGHT_P2P_RELAY_FORWARD_DEDUP_WINDOW_SECS", 30)?);
        let relay_forward_dedup_capacity =
            env_usize("SOVRIGHT_P2P_RELAY_FORWARD_DEDUP_CAPACITY", 64)?;
        let submitblock_rpc = submitblock_rpc_from_env()?;

        if seeds.is_empty() && peers.is_empty() {
            return Err(IngressError::Config(
                "configure at least one DNS seed or peer".to_string(),
            ));
        }

        Ok(Self {
            seeds,
            peers,
            max_peers,
            connect_timeout,
            peer_runtime,
            crawler_enabled,
            crawler_max_known_peers,
            crawler_max_addr_per_message,
            crawler_drain_interval,
            rotation_enabled,
            rotation_cooldown,
            rotation_failure_cooldown,
            accept_nonstandard_ports,
            peer_scoring_enabled,
            peer_score_block_inv,
            peer_score_block_received,
            peer_score_relay_forwarded,
            peer_score_error,
            tx_cache_enabled,
            tx_cache_max_entries,
            tx_cache_max_bytes,
            tx_cache_max_tx_bytes,
            tx_feed_addr,
            tx_request_limit_per_inv,
            event_log,
            relay_peers,
            relay_bind_addr,
            relay_auth_key,
            relay_data_shards,
            relay_parity_shards,
            relay_adaptive_fec,
            relay_send_burst_packets,
            relay_send_burst_delay_micros,
            relay_compact_from_tx_cache,
            relay_skeleton_first,
            relay_raw_fallback_with_tx_cache,
            relay_raw_segment_send_rounds,
            relay_raw_segment_round_delay_millis,
            relay_forward_dedup_window,
            relay_forward_dedup_capacity,
            submitblock_rpc,
        })
    }
}

fn submitblock_rpc_from_env() -> Result<Option<SubmitBlockRpcConfig>> {
    let Some(bind_addr) = env_optional_socket("SOVRIGHT_P2P_SUBMITBLOCK_RPC_BIND_ADDR")? else {
        return Ok(None);
    };
    if !bind_addr.ip().is_loopback() {
        return Err(IngressError::Config(
            "SOVRIGHT_P2P_SUBMITBLOCK_RPC_BIND_ADDR must be loopback; put an authenticated TLS proxy in front for remote pool access"
                .to_string(),
        ));
    }

    let zebra_url = env::var("SOVRIGHT_P2P_SUBMITBLOCK_ZEBRA_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8232".to_string());
    if !is_loopback_http_url(&zebra_url) {
        return Err(IngressError::Config(
            "SOVRIGHT_P2P_SUBMITBLOCK_ZEBRA_URL must use http:// with a loopback host".to_string(),
        ));
    }

    let max_block_bytes = env_usize(
        "SOVRIGHT_P2P_SUBMITBLOCK_MAX_BLOCK_BYTES",
        DEFAULT_SUBMITBLOCK_MAX_BLOCK_BYTES,
    )?;
    if max_block_bytes < sovright_relay::ZCASH_FULL_HEADER_SIZE {
        return Err(IngressError::Config(format!(
            "SOVRIGHT_P2P_SUBMITBLOCK_MAX_BLOCK_BYTES must be at least {}",
            sovright_relay::ZCASH_FULL_HEADER_SIZE
        )));
    }
    let max_requests_per_minute = env_usize("SOVRIGHT_P2P_SUBMITBLOCK_MAX_REQUESTS_PER_MINUTE", 4)?;
    if max_requests_per_minute == 0 || max_requests_per_minute > 120 {
        return Err(IngressError::Config(
            "SOVRIGHT_P2P_SUBMITBLOCK_MAX_REQUESTS_PER_MINUTE must be between 1 and 120"
                .to_string(),
        ));
    }
    let relay_timeout_millis = env_u64("SOVRIGHT_P2P_SUBMITBLOCK_RELAY_TIMEOUT_MILLIS", 1_000)?;
    if relay_timeout_millis == 0 || relay_timeout_millis > 10_000 {
        return Err(IngressError::Config(
            "SOVRIGHT_P2P_SUBMITBLOCK_RELAY_TIMEOUT_MILLIS must be between 1 and 10000".to_string(),
        ));
    }

    Ok(Some(SubmitBlockRpcConfig {
        bind_addr,
        zebra_url,
        max_block_bytes,
        max_requests_per_minute,
        relay_timeout: Duration::from_millis(relay_timeout_millis),
    }))
}

fn is_loopback_http_url(value: &str) -> bool {
    // Case-insensitive: the scheme and `localhost` are case-insensitive per URL
    // rules, so `http://Localhost` is as valid a loopback as `http://localhost`.
    // IP literals are unaffected by lowercasing. This stays fail-closed for
    // spoofs like `localhost.evil.com` or `evil.com@127.0.0.1` (still rejected).
    let value = value.to_ascii_lowercase();
    let Some(authority_and_path) = value.strip_prefix("http://") else {
        return false;
    };
    let authority = authority_and_path.split('/').next().unwrap_or_default();
    authority == "localhost"
        || authority.starts_with("localhost:")
        || authority == "127.0.0.1"
        || authority.starts_with("127.0.0.1:")
        || authority == "[::1]"
        || authority.starts_with("[::1]:")
}

pub fn default_seeds() -> Vec<String> {
    vec![
        "dnsseed.z.cash".to_string(),
        "dnsseed.str4d.xyz".to_string(),
        "mainnet.seeder.zfnd.org".to_string(),
        "mainnet.is.yolo.money".to_string(),
    ]
}

fn env_csv(name: &str) -> Option<Vec<String>> {
    env::var(name).ok().map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    })
}

fn env_socket_csv(name: &str) -> Result<Vec<SocketAddr>> {
    let Some(values) = env_csv(name) else {
        return Ok(Vec::new());
    };
    values
        .into_iter()
        .map(|value| {
            value.parse().map_err(|e| {
                IngressError::Config(format!("invalid socket address in {name}: {value}: {e}"))
            })
        })
        .collect()
}

fn env_optional_socket(name: &str) -> Result<Option<SocketAddr>> {
    let Ok(value) = env::var(name) else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed.parse().map(Some).map_err(|e| {
        IngressError::Config(format!("invalid socket address in {name}: {trimmed}: {e}"))
    })
}

fn env_usize(name: &str, default: usize) -> Result<usize> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|e| IngressError::Config(format!("invalid {name}: {e}"))),
        Err(_) => Ok(default),
    }
}

fn env_u64(name: &str, default: u64) -> Result<u64> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|e| IngressError::Config(format!("invalid {name}: {e}"))),
        Err(_) => Ok(default),
    }
}

fn env_i64(name: &str, default: i64) -> Result<i64> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|e| IngressError::Config(format!("invalid {name}: {e}"))),
        Err(_) => Ok(default),
    }
}

fn env_bool(name: &str, default: bool) -> Result<bool> {
    match env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(IngressError::Config(format!("invalid {name}: {value}"))),
        },
        Err(_) => Ok(default),
    }
}

fn parse_auth_key(value: &str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(value.trim(), &mut out)
        .map_err(|e| IngressError::Config(format!("invalid relay auth key hex: {e}")))?;
    Ok(out)
}

pub fn seed_socket(seed: &str) -> String {
    if seed.contains(':') {
        seed.to_string()
    } else {
        format!("{seed}:{DEFAULT_PORT}")
    }
}

pub fn is_denied_peer_addr(peer: &SocketAddr) -> bool {
    DENIED_PEER_PORTS.contains(&peer.port())
}

pub fn is_accepted_peer_addr(peer: &SocketAddr, accept_nonstandard_ports: bool) -> bool {
    !is_denied_peer_addr(peer) && (accept_nonstandard_ports || peer.port() == DEFAULT_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn set(vars: &[(&'static str, String)]) -> Self {
            let saved = vars
                .iter()
                .map(|(name, _)| (*name, env::var(name).ok()))
                .collect();
            unsafe {
                for (name, value) in vars {
                    env::set_var(name, value);
                }
            }
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                for (name, value) in &self.saved {
                    match value {
                        Some(value) => env::set_var(name, value),
                        None => env::remove_var(name),
                    }
                }
            }
        }
    }

    #[test]
    fn seed_socket_adds_default_port() {
        assert_eq!(seed_socket("dnsseed.z.cash"), "dnsseed.z.cash:8233");
        assert_eq!(seed_socket("127.0.0.1:8233"), "127.0.0.1:8233");
    }

    #[test]
    fn parses_auth_key() {
        let key = parse_auth_key(&"42".repeat(32)).unwrap();
        assert_eq!(key, [0x42; 32]);
    }

    #[test]
    fn identifies_known_zcash_fork_ports() {
        assert!(is_denied_peer_addr(&"127.0.0.1:16125".parse().unwrap()));
        assert!(is_denied_peer_addr(&"127.0.0.1:26125".parse().unwrap()));
        assert!(!is_denied_peer_addr(&"127.0.0.1:8233".parse().unwrap()));
    }

    #[test]
    fn accepts_standard_port_by_default() {
        assert!(is_accepted_peer_addr(
            &"127.0.0.1:8233".parse().unwrap(),
            false
        ));
        assert!(!is_accepted_peer_addr(
            &"127.0.0.1:34567".parse().unwrap(),
            false
        ));
        assert!(is_accepted_peer_addr(
            &"127.0.0.1:34567".parse().unwrap(),
            true
        ));
        assert!(!is_accepted_peer_addr(
            &"127.0.0.1:16125".parse().unwrap(),
            true
        ));
    }

    #[test]
    fn parses_optional_socket_env() {
        let key = format!(
            "SOVRIGHT_P2P_TEST_TX_FEED_ADDR_{}_{}",
            std::process::id(),
            19091
        );
        unsafe {
            std::env::set_var(&key, "127.0.0.1:19091");
        }

        assert_eq!(
            env_optional_socket(&key).unwrap(),
            Some("127.0.0.1:19091".parse().unwrap())
        );

        unsafe {
            std::env::remove_var(&key);
        }
    }

    #[test]
    fn submitblock_rpc_defaults_off() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(&[
            ("SOVRIGHT_P2P_DNS_SEEDS", "dnsseed.z.cash".to_string()),
            ("SOVRIGHT_P2P_SUBMITBLOCK_RPC_BIND_ADDR", "".to_string()),
        ]);

        let config = Config::from_env().unwrap();

        assert_eq!(config.submitblock_rpc, None);
    }

    #[test]
    fn parses_loopback_submitblock_rpc() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(&[
            ("SOVRIGHT_P2P_DNS_SEEDS", "dnsseed.z.cash".to_string()),
            (
                "SOVRIGHT_P2P_SUBMITBLOCK_RPC_BIND_ADDR",
                "127.0.0.1:8234".to_string(),
            ),
            (
                "SOVRIGHT_P2P_SUBMITBLOCK_ZEBRA_URL",
                "http://127.0.0.1:8232".to_string(),
            ),
            (
                "SOVRIGHT_P2P_SUBMITBLOCK_MAX_BLOCK_BYTES",
                "2097152".to_string(),
            ),
        ]);

        let config = Config::from_env().unwrap();

        assert_eq!(
            config.submitblock_rpc,
            Some(SubmitBlockRpcConfig {
                bind_addr: "127.0.0.1:8234".parse().unwrap(),
                zebra_url: "http://127.0.0.1:8232".to_string(),
                max_block_bytes: 2_097_152,
                max_requests_per_minute: 4,
                relay_timeout: Duration::from_secs(1),
            })
        );
    }

    #[test]
    fn rejects_non_loopback_submitblock_rpc_listener() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(&[
            ("SOVRIGHT_P2P_DNS_SEEDS", "dnsseed.z.cash".to_string()),
            (
                "SOVRIGHT_P2P_SUBMITBLOCK_RPC_BIND_ADDR",
                "0.0.0.0:8234".to_string(),
            ),
        ]);

        let error = Config::from_env().unwrap_err();

        assert!(error.to_string().contains("must be loopback"), "{error}");
    }

    #[test]
    fn rejects_non_loopback_submitblock_zebra_url() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(&[
            ("SOVRIGHT_P2P_DNS_SEEDS", "dnsseed.z.cash".to_string()),
            (
                "SOVRIGHT_P2P_SUBMITBLOCK_RPC_BIND_ADDR",
                "127.0.0.1:8234".to_string(),
            ),
            (
                "SOVRIGHT_P2P_SUBMITBLOCK_ZEBRA_URL",
                "http://10.0.0.2:8232".to_string(),
            ),
        ]);

        let error = Config::from_env().unwrap_err();

        assert!(error.to_string().contains("loopback host"), "{error}");
    }

    #[test]
    fn recognizes_only_explicit_loopback_http_urls() {
        assert!(is_loopback_http_url("http://127.0.0.1:8232"));
        assert!(is_loopback_http_url("http://localhost:8232/"));
        assert!(is_loopback_http_url("http://[::1]:8232"));
        // Scheme and `localhost` are case-insensitive.
        assert!(is_loopback_http_url("http://Localhost:8232"));
        assert!(is_loopback_http_url("HTTP://127.0.0.1:8232"));
        assert!(!is_loopback_http_url("https://127.0.0.1:8232"));
        assert!(!is_loopback_http_url("http://127.0.0.1.example:8232"));
        assert!(!is_loopback_http_url("http://10.0.0.2:8232"));
        // Spoofs remain fail-closed even after lowercasing.
        assert!(!is_loopback_http_url("http://localhost.evil.com:8232"));
        assert!(!is_loopback_http_url("http://evil.com@127.0.0.1:8232"));
    }

    #[test]
    fn parses_raw_segment_retransmission_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(&[
            ("SOVRIGHT_P2P_DNS_SEEDS", "dnsseed.z.cash".to_string()),
            ("SOVRIGHT_P2P_PEERS", "".to_string()),
            ("SOVRIGHT_P2P_RELAY_PEERS", "".to_string()),
            ("SOVRIGHT_P2P_RELAY_AUTH_KEY_HEX", "42".repeat(32)),
            (
                "SOVRIGHT_P2P_RELAY_RAW_SEGMENT_SEND_ROUNDS",
                "3".to_string(),
            ),
            (
                "SOVRIGHT_P2P_RELAY_RAW_SEGMENT_ROUND_DELAY_MILLIS",
                "25".to_string(),
            ),
        ]);

        let config = Config::from_env().unwrap();

        assert_eq!(config.relay_raw_segment_send_rounds, 3);
        assert_eq!(config.relay_raw_segment_round_delay_millis, 25);
    }

    #[test]
    fn parses_relay_adaptive_fec_flag() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(&[
            ("SOVRIGHT_P2P_DNS_SEEDS", "dnsseed.z.cash".to_string()),
            ("SOVRIGHT_P2P_PEERS", "".to_string()),
            ("SOVRIGHT_P2P_RELAY_PEERS", "".to_string()),
            ("SOVRIGHT_P2P_RELAY_ADAPTIVE_FEC", "true".to_string()),
        ]);

        let config = Config::from_env().unwrap();
        assert!(config.relay_adaptive_fec);
    }

    #[test]
    fn relay_adaptive_fec_parses_false() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(&[
            ("SOVRIGHT_P2P_DNS_SEEDS", "dnsseed.z.cash".to_string()),
            ("SOVRIGHT_P2P_PEERS", "".to_string()),
            ("SOVRIGHT_P2P_RELAY_PEERS", "".to_string()),
            ("SOVRIGHT_P2P_RELAY_ADAPTIVE_FEC", "false".to_string()),
        ]);

        let config = Config::from_env().unwrap();
        assert!(!config.relay_adaptive_fec);
    }

    #[test]
    fn relay_skeleton_first_defaults_off_and_parses_true() {
        let _lock = ENV_LOCK.lock().unwrap();
        {
            let _guard = EnvGuard::set(&[
                ("SOVRIGHT_P2P_DNS_SEEDS", "dnsseed.z.cash".to_string()),
                ("SOVRIGHT_P2P_PEERS", "".to_string()),
                ("SOVRIGHT_P2P_RELAY_PEERS", "".to_string()),
            ]);
            let config = Config::from_env().unwrap();
            assert!(!config.relay_skeleton_first, "defaults off");
        }
        {
            let _guard = EnvGuard::set(&[
                ("SOVRIGHT_P2P_DNS_SEEDS", "dnsseed.z.cash".to_string()),
                ("SOVRIGHT_P2P_PEERS", "".to_string()),
                ("SOVRIGHT_P2P_RELAY_PEERS", "".to_string()),
                ("SOVRIGHT_P2P_RELAY_SKELETON_FIRST", "true".to_string()),
            ]);
            let config = Config::from_env().unwrap();
            assert!(config.relay_skeleton_first);
        }
    }

    #[test]
    fn rejects_zero_raw_segment_send_rounds() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(&[
            ("SOVRIGHT_P2P_DNS_SEEDS", "dnsseed.z.cash".to_string()),
            (
                "SOVRIGHT_P2P_RELAY_RAW_SEGMENT_SEND_ROUNDS",
                "0".to_string(),
            ),
        ]);

        let err = Config::from_env().unwrap_err();

        assert!(
            err.to_string()
                .contains("SOVRIGHT_P2P_RELAY_RAW_SEGMENT_SEND_ROUNDS must be at least 1"),
            "{err}"
        );
    }
}
