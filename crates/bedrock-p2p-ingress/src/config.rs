use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{IngressError, Result};
use crate::wire::DEFAULT_PORT;

/// Known Zcash forks that reused the Zcash network magic and gossip into
/// Zcash address books, but whose blocks are not Zcash mainnet blocks.
const DENIED_PEER_PORTS: &[u16] = &[16_125, 26_125];

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
    pub peer_score_forge_forwarded: i64,
    pub peer_score_error: i64,
    pub tx_cache_enabled: bool,
    pub tx_cache_max_entries: usize,
    pub tx_cache_max_bytes: usize,
    pub tx_cache_max_tx_bytes: usize,
    pub tx_request_limit_per_inv: usize,
    pub event_log: Option<PathBuf>,
    pub relay_peers: Vec<SocketAddr>,
    pub relay_bind_addr: SocketAddr,
    pub relay_auth_key: Option<[u8; 32]>,
    pub relay_data_shards: usize,
    pub relay_parity_shards: usize,
    pub relay_send_burst_packets: usize,
    pub relay_send_burst_delay_micros: u64,
    pub relay_compact_from_tx_cache: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let seeds = env_csv("BEDROCK_P2P_DNS_SEEDS").unwrap_or_else(default_seeds);
        let peers = env_socket_csv("BEDROCK_P2P_PEERS")?;
        let max_peers = env_usize("BEDROCK_P2P_MAX_PEERS", 8)?;
        let connect_timeout = Duration::from_secs(env_u64("BEDROCK_P2P_CONNECT_TIMEOUT_SECS", 5)?);
        let peer_runtime = Duration::from_secs(env_u64("BEDROCK_P2P_PEER_RUNTIME_SECS", 0)?);
        let crawler_enabled = env_bool("BEDROCK_P2P_CRAWLER_ENABLED", false)?;
        let crawler_max_known_peers = env_usize("BEDROCK_P2P_CRAWLER_MAX_KNOWN_PEERS", 5_000)?;
        let crawler_max_addr_per_message =
            env_usize("BEDROCK_P2P_CRAWLER_MAX_ADDR_PER_MESSAGE", 1_000)?;
        let crawler_drain_interval =
            Duration::from_secs(env_u64("BEDROCK_P2P_CRAWLER_DRAIN_INTERVAL_SECS", 5)?);
        let rotation_enabled = env_bool("BEDROCK_P2P_ROTATION_ENABLED", false)?;
        let rotation_cooldown =
            Duration::from_secs(env_u64("BEDROCK_P2P_ROTATION_COOLDOWN_SECS", 30)?);
        let rotation_failure_cooldown =
            Duration::from_secs(env_u64("BEDROCK_P2P_ROTATION_FAILURE_COOLDOWN_SECS", 120)?);
        let accept_nonstandard_ports = env_bool("BEDROCK_P2P_ACCEPT_NONSTANDARD_PORTS", false)?;
        let peer_scoring_enabled = env_bool("BEDROCK_P2P_PEER_SCORING_ENABLED", false)?;
        let peer_score_block_inv = env_i64("BEDROCK_P2P_PEER_SCORE_BLOCK_INV", 5)?;
        let peer_score_block_received = env_i64("BEDROCK_P2P_PEER_SCORE_BLOCK_RECEIVED", 25)?;
        let peer_score_forge_forwarded = env_i64("BEDROCK_P2P_PEER_SCORE_FORGE_FORWARDED", 10)?;
        let peer_score_error = env_i64("BEDROCK_P2P_PEER_SCORE_ERROR", -50)?;
        let tx_cache_enabled = env_bool("BEDROCK_P2P_TX_CACHE_ENABLED", false)?;
        let tx_cache_max_entries = env_usize("BEDROCK_P2P_TX_CACHE_MAX_ENTRIES", 200_000)?;
        let tx_cache_max_bytes = env_usize("BEDROCK_P2P_TX_CACHE_MAX_BYTES", 536_870_912)?;
        let tx_cache_max_tx_bytes = env_usize("BEDROCK_P2P_TX_CACHE_MAX_TX_BYTES", 2_097_152)?;
        let tx_request_limit_per_inv = env_usize("BEDROCK_P2P_TX_REQUEST_LIMIT_PER_INV", 256)?;
        let event_log = env::var("BEDROCK_P2P_EVENT_LOG").ok().map(PathBuf::from);
        let relay_peers = env_socket_csv("BEDROCK_P2P_RELAY_PEERS")?;
        let relay_bind_addr = env::var("BEDROCK_P2P_RELAY_BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:0".to_string())
            .parse()
            .map_err(|e| {
                IngressError::Config(format!("invalid BEDROCK_P2P_RELAY_BIND_ADDR: {e}"))
            })?;
        let relay_auth_key = match env::var("BEDROCK_P2P_RELAY_AUTH_KEY_HEX") {
            Ok(value) => Some(parse_auth_key(&value)?),
            Err(_) => None,
        };
        let relay_data_shards = env_usize("BEDROCK_P2P_RELAY_DATA_SHARDS", 10)?;
        let relay_parity_shards = env_usize("BEDROCK_P2P_RELAY_PARITY_SHARDS", 3)?;
        let relay_send_burst_packets = env_usize("BEDROCK_P2P_RELAY_SEND_BURST_PACKETS", 0)?;
        let relay_send_burst_delay_micros =
            env_u64("BEDROCK_P2P_RELAY_SEND_BURST_DELAY_MICROS", 0)?;
        let relay_compact_from_tx_cache =
            env_bool("BEDROCK_P2P_RELAY_COMPACT_FROM_TX_CACHE", false)?;

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
            peer_score_forge_forwarded,
            peer_score_error,
            tx_cache_enabled,
            tx_cache_max_entries,
            tx_cache_max_bytes,
            tx_cache_max_tx_bytes,
            tx_request_limit_per_inv,
            event_log,
            relay_peers,
            relay_bind_addr,
            relay_auth_key,
            relay_data_shards,
            relay_parity_shards,
            relay_send_burst_packets,
            relay_send_burst_delay_micros,
            relay_compact_from_tx_cache,
        })
    }
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
}
