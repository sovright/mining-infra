use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{IngressError, Result};
use crate::wire::DEFAULT_PORT;

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
    pub event_log: Option<PathBuf>,
    pub relay_peers: Vec<SocketAddr>,
    pub relay_bind_addr: SocketAddr,
    pub relay_auth_key: Option<[u8; 32]>,
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
            event_log,
            relay_peers,
            relay_bind_addr,
            relay_auth_key,
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
}
