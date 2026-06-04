//! Configuration file support

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

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

    /// Poll interval in milliseconds
    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,
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
        assert_eq!(config.poll_interval_ms, 100);
    }
}
