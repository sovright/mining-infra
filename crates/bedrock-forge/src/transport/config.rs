//! Relay configuration

use std::net::SocketAddr;
use std::time::Duration;

use crate::transport::{MAX_PAYLOAD_SIZE, TransportError};

/// Maximum total shards for Reed-Solomon (8-bit)
const MAX_TOTAL_SHARDS: usize = 256;

/// Configuration for a relay node
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Address to listen on
    pub listen_addr: SocketAddr,
    /// Number of FEC data shards
    pub data_shards: usize,
    /// Number of FEC parity shards
    pub parity_shards: usize,
    /// Maximum payload size per chunk
    pub chunk_size: usize,
    /// Session timeout duration
    pub session_timeout: Duration,
    /// Block assembly timeout
    pub assembly_timeout: Duration,
    /// Pre-shared keys for authorized clients
    pub authorized_keys: Vec<[u8; 32]>,
    /// Explicitly allow unauthenticated peers (unsafe outside tests/dev)
    pub allow_unauthenticated_peers: bool,
    /// Maximum number of active peer sessions to retain
    pub max_sessions: usize,
    /// Number of forwarded packets to send before applying `forward_burst_delay`.
    /// Zero disables relay-side forward pacing.
    pub forward_burst_packets: usize,
    /// Optional delay after each forwarded packet burst.
    pub forward_burst_delay: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8333".parse().unwrap(),
            data_shards: 10,
            parity_shards: 3,
            chunk_size: MAX_PAYLOAD_SIZE,
            session_timeout: Duration::from_secs(300),
            assembly_timeout: Duration::from_secs(30),
            authorized_keys: Vec::new(),
            allow_unauthenticated_peers: false,
            max_sessions: 4096,
            forward_burst_packets: 0,
            forward_burst_delay: Duration::ZERO,
        }
    }
}

impl RelayConfig {
    /// Create a new config with the given listen address
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            ..Default::default()
        }
    }

    /// Builder method: set authorized keys
    pub fn with_authorized_keys(mut self, keys: Vec<[u8; 32]>) -> Self {
        self.authorized_keys = keys;
        self
    }

    /// Builder method: explicitly allow unauthenticated peers
    pub fn with_unauthenticated_peers_allowed(mut self, allowed: bool) -> Self {
        self.allow_unauthenticated_peers = allowed;
        self
    }

    /// Builder method: set max active sessions
    pub fn with_max_sessions(mut self, max_sessions: usize) -> Self {
        self.max_sessions = max_sessions;
        self
    }

    /// Builder method: set relay-side outbound packet pacing
    pub fn with_forward_pacing(mut self, burst_packets: usize, burst_delay: Duration) -> Self {
        self.forward_burst_packets = burst_packets;
        self.forward_burst_delay = burst_delay;
        self
    }

    /// Builder method: set FEC parameters
    pub fn with_fec(mut self, data_shards: usize, parity_shards: usize) -> Self {
        self.data_shards = data_shards;
        self.parity_shards = parity_shards;
        self
    }

    /// Builder method: set timeouts
    pub fn with_timeouts(mut self, session: Duration, assembly: Duration) -> Self {
        self.session_timeout = session;
        self.assembly_timeout = assembly;
        self
    }

    /// Get total number of shards
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Whether relay authentication is required for inbound peers.
    ///
    /// Auth is required when `allow_unauthenticated_peers` is false.
    /// When auth IS required, `authorized_keys` is used to validate
    /// peer credentials -- but the presence of keys alone does not
    /// force auth on (a relay may keep a key list for optional
    /// verification while still allowing unauthenticated peers).
    pub fn auth_required(&self) -> bool {
        !self.allow_unauthenticated_peers
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.data_shards == 0 {
            return Err(TransportError::InvalidChunk(
                "data_shards must be > 0".into(),
            ));
        }
        if self.parity_shards == 0 {
            return Err(TransportError::InvalidChunk(
                "parity_shards must be > 0".into(),
            ));
        }
        if self.data_shards + self.parity_shards > MAX_TOTAL_SHARDS {
            return Err(TransportError::InvalidChunk(format!(
                "total shards ({}) exceeds maximum ({})",
                self.data_shards + self.parity_shards,
                MAX_TOTAL_SHARDS
            )));
        }
        if self.chunk_size == 0 {
            return Err(TransportError::InvalidChunk(
                "chunk_size must be > 0".into(),
            ));
        }
        if self.chunk_size > MAX_PAYLOAD_SIZE {
            return Err(TransportError::InvalidChunk(format!(
                "chunk_size ({}) exceeds max payload size ({})",
                self.chunk_size, MAX_PAYLOAD_SIZE
            )));
        }
        if self.max_sessions == 0 {
            return Err(TransportError::InvalidChunk(
                "max_sessions must be > 0".into(),
            ));
        }
        if self.forward_burst_packets == 0 && !self.forward_burst_delay.is_zero() {
            return Err(TransportError::InvalidChunk(
                "forward_burst_packets must be > 0 when forward_burst_delay is set".into(),
            ));
        }
        if self.authorized_keys.is_empty() && !self.allow_unauthenticated_peers {
            return Err(TransportError::ConnectionRefused(
                "authorized_keys required unless unauthenticated peers are explicitly allowed"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Configuration for a relay client
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Relay node addresses to connect to
    pub relay_addrs: Vec<SocketAddr>,
    /// Authentication key
    pub auth_key: [u8; 32],
    /// Number of FEC data shards (must match relay)
    pub data_shards: usize,
    /// Number of FEC parity shards (must match relay)
    pub parity_shards: usize,
    /// Local bind address (0.0.0.0:0 for auto)
    pub bind_addr: SocketAddr,
    /// Receive timeout
    pub recv_timeout: Duration,
    /// Whether authenticated chunks are required for inbound traffic
    pub auth_required: bool,
    /// Number of outbound packets to send before applying `send_burst_delay`.
    /// Zero disables client-side send pacing.
    pub send_burst_packets: usize,
    /// Optional delay after each outbound packet burst.
    pub send_burst_delay: Duration,
}

impl ClientConfig {
    /// Create a new client config
    pub fn new(relay_addrs: Vec<SocketAddr>, auth_key: [u8; 32]) -> Self {
        Self {
            relay_addrs,
            auth_key,
            data_shards: 10,
            parity_shards: 3,
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            recv_timeout: Duration::from_secs(30),
            auth_required: false,
            send_burst_packets: 0,
            send_burst_delay: Duration::ZERO,
        }
    }

    /// Builder method: set FEC parameters
    pub fn with_fec(mut self, data_shards: usize, parity_shards: usize) -> Self {
        self.data_shards = data_shards;
        self.parity_shards = parity_shards;
        self
    }

    /// Builder method: set bind address
    pub fn with_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Builder method: set auth requirement for inbound chunks
    pub fn with_auth_required(mut self, required: bool) -> Self {
        self.auth_required = required;
        self
    }

    /// Builder method: set client-side outbound packet pacing
    pub fn with_send_pacing(mut self, burst_packets: usize, burst_delay: Duration) -> Self {
        self.send_burst_packets = burst_packets;
        self.send_burst_delay = burst_delay;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.data_shards == 0 {
            return Err(TransportError::InvalidChunk(
                "data_shards must be > 0".into(),
            ));
        }
        if self.parity_shards == 0 {
            return Err(TransportError::InvalidChunk(
                "parity_shards must be > 0".into(),
            ));
        }
        if self.data_shards + self.parity_shards > MAX_TOTAL_SHARDS {
            return Err(TransportError::InvalidChunk(format!(
                "total shards ({}) exceeds maximum ({})",
                self.data_shards + self.parity_shards,
                MAX_TOTAL_SHARDS
            )));
        }
        if self.relay_addrs.is_empty() {
            return Err(TransportError::InvalidChunk(
                "relay_addrs must not be empty".into(),
            ));
        }
        if self.auth_required && self.auth_key == [0u8; 32] {
            return Err(TransportError::InvalidChunk(
                "auth_required set but auth_key is all zeros".into(),
            ));
        }
        if self.send_burst_packets == 0 && !self.send_burst_delay.is_zero() {
            return Err(TransportError::InvalidChunk(
                "send_burst_packets must be > 0 when send_burst_delay is set".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_config_defaults() {
        let config = RelayConfig::default();
        assert_eq!(config.data_shards, 10);
        assert_eq!(config.parity_shards, 3);
        assert_eq!(config.total_shards(), 13);
        assert_eq!(config.forward_burst_packets, 0);
        assert!(config.forward_burst_delay.is_zero());
    }

    #[test]
    fn relay_config_builder() {
        let keys = vec![[0x42; 32]];
        let config = RelayConfig::new("127.0.0.1:9000".parse().unwrap())
            .with_authorized_keys(keys.clone())
            .with_fec(8, 4)
            .with_forward_pacing(32, Duration::from_millis(1));

        assert_eq!(config.listen_addr.port(), 9000);
        assert_eq!(config.authorized_keys, keys);
        assert_eq!(config.data_shards, 8);
        assert_eq!(config.parity_shards, 4);
        assert_eq!(config.forward_burst_packets, 32);
        assert_eq!(config.forward_burst_delay, Duration::from_millis(1));
    }

    #[test]
    fn client_config_builder() {
        let relays = vec!["127.0.0.1:8333".parse().unwrap()];
        let key = [0xab; 32];
        let config = ClientConfig::new(relays.clone(), key)
            .with_fec(10, 3)
            .with_send_pacing(32, Duration::from_millis(1));

        assert_eq!(config.relay_addrs, relays);
        assert_eq!(config.auth_key, key);
        assert_eq!(config.data_shards, 10);
        assert_eq!(config.send_burst_packets, 32);
        assert_eq!(config.send_burst_delay, Duration::from_millis(1));
    }

    #[test]
    fn relay_config_validation() {
        // Valid config
        assert!(RelayConfig::default().validate().is_err());

        let valid_config = RelayConfig::default().with_unauthenticated_peers_allowed(true);
        assert!(valid_config.validate().is_ok());

        // Invalid data shards
        let config = RelayConfig {
            data_shards: 0,
            ..RelayConfig::default()
        };
        assert!(config.validate().is_err());

        // Invalid parity shards
        let config = RelayConfig {
            parity_shards: 0,
            ..RelayConfig::default()
        };
        assert!(config.validate().is_err());

        // Too many shards
        let config = RelayConfig {
            data_shards: 200,
            parity_shards: 100,
            ..RelayConfig::default()
        };
        assert!(config.validate().is_err());

        let invalid_pacing = RelayConfig::default()
            .with_unauthenticated_peers_allowed(true)
            .with_forward_pacing(0, Duration::from_millis(1));
        assert!(invalid_pacing.validate().is_err());
    }

    #[test]
    fn client_config_validation() {
        let relays = vec!["127.0.0.1:8333".parse().unwrap()];
        let key = [0xab; 32];

        // Valid config
        assert!(ClientConfig::new(relays.clone(), key).validate().is_ok());

        // Empty relay addrs
        assert!(ClientConfig::new(vec![], key).validate().is_err());
        assert!(
            ClientConfig::new(relays, [0u8; 32])
                .with_auth_required(true)
                .validate()
                .is_err()
        );

        let invalid_pacing = ClientConfig::new(vec!["127.0.0.1:8333".parse().unwrap()], key)
            .with_send_pacing(0, Duration::from_millis(1));
        assert!(invalid_pacing.validate().is_err());
    }
}
