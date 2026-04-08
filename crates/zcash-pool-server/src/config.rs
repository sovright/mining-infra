//! Pool server configuration

use std::net::SocketAddr;
use std::path::PathBuf;
use zcash_jd_server::ValidationLevel;

/// Pool server configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Address to listen on for miner connections
    pub listen_addr: SocketAddr,

    /// Zebra RPC URL for template provider
    pub zebra_url: String,

    /// Template polling interval in milliseconds
    pub template_poll_ms: u64,

    /// Number of validation threads (each needs ~144MB for Equihash)
    pub validation_threads: usize,

    /// Default nonce_1 length (pool prefix)
    pub nonce_1_len: u8,

    /// Initial share difficulty
    pub initial_difficulty: f64,

    /// Vardiff target shares per minute
    pub target_shares_per_minute: f64,

    /// Maximum concurrent connections
    pub max_connections: usize,

    /// Optional: JD Server listen address (enables Job Declaration support)
    pub jd_listen_addr: Option<SocketAddr>,

    /// Pool's payout script for coinbase (used by JD Server)
    pub pool_payout_script: Option<Vec<u8>>,

    /// Enable Noise encryption for miner connections
    pub noise_enabled: bool,

    /// Path to server private key file (hex-encoded)
    pub noise_private_key_path: Option<PathBuf>,

    /// Enable Noise for JD connections
    pub jd_noise_enabled: bool,

    /// Enable Full-Template mode for JD server
    pub jd_full_template_enabled: bool,

    /// Validation level for Full-Template mode
    pub jd_full_template_validation: ValidationLevel,

    /// Minimum pool payout value (zatoshis) for Full-Template mode
    pub jd_min_pool_payout: u64,

    /// Metrics server address
    pub metrics_addr: Option<SocketAddr>,

    /// Use JSON logging format
    pub json_logging: bool,

    /// OTLP endpoint for distributed tracing
    pub otlp_endpoint: Option<String>,

    /// Forge relay configuration (optional - None disables relay)
    pub forge_relay_enabled: bool,
    /// UDP bind address for forge relay (default: 0.0.0.0:8336)
    pub forge_bind_addr: Option<SocketAddr>,
    /// Relay peer addresses to connect to
    pub forge_relay_peers: Vec<SocketAddr>,
    /// Shared authentication key for relay network (32 bytes)
    pub forge_auth_key: Option<[u8; 32]>,
    /// FEC data shards (default: 10)
    pub forge_data_shards: usize,
    /// FEC parity shards (default: 3)
    pub forge_parity_shards: usize,

    // Security settings (attack mitigation)
    /// Enable sequence validation for replay attack protection
    pub sequence_validation_enabled: bool,
    /// Maximum allowed gap in sequence numbers (for out-of-order handling)
    pub sequence_max_gap: u32,
    /// Enable connection pattern tracking (EROSION attack detection)
    pub connection_tracking_enabled: bool,
    /// Threshold for "short-lived" connections in seconds
    pub short_lived_threshold_secs: u64,
    /// Maximum short-lived connections before flagging an address
    pub max_short_lived_per_window: usize,
    /// Enable timing jitter for share responses (timing attack mitigation)
    pub timing_jitter_enabled: bool,
    /// Minimum timing jitter in milliseconds
    pub timing_jitter_min_ms: u64,
    /// Maximum timing jitter in milliseconds
    pub timing_jitter_max_ms: u64,
    /// Warn if Noise is disabled (plain mode is insecure)
    pub warn_plain_mode: bool,
}

/// Configuration validation errors
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigError {
    /// Invalid nonce_1_len (must be 1-31 to leave room for nonce_2)
    InvalidNonce1Len(u8),
    /// Invalid difficulty (must be positive)
    InvalidDifficulty(f64),
    /// Invalid target shares per minute (must be positive)
    InvalidTargetSharesPerMinute(f64),
    /// Invalid validation threads (must be at least 1)
    InvalidValidationThreads(usize),
    /// Invalid template poll interval (must be at least 100ms)
    InvalidTemplatePollMs(u64),
    /// Invalid max connections (must be at least 1)
    InvalidMaxConnections(usize),
    /// Forge relay enabled but no auth key provided
    ForgeMissingAuthKey,
    /// Invalid FEC shard configuration
    InvalidFecConfig { data: usize, parity: usize },
    /// JD enabled but no pool payout script
    JdMissingPayoutScript,
    /// Invalid timing jitter configuration (min > max)
    InvalidTimingJitter { min_ms: u64, max_ms: u64 },
    /// Invalid FEC shard total (must be <= 255 for Reed-Solomon)
    InvalidFecShardTotal { total: usize },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::InvalidNonce1Len(v) => write!(f, "nonce_1_len {} must be 1-31", v),
            ConfigError::InvalidDifficulty(v) => write!(f, "initial_difficulty {} must be positive", v),
            ConfigError::InvalidTargetSharesPerMinute(v) => {
                write!(f, "target_shares_per_minute {} must be positive", v)
            }
            ConfigError::InvalidValidationThreads(v) => {
                write!(f, "validation_threads {} must be at least 1", v)
            }
            ConfigError::InvalidTemplatePollMs(v) => {
                write!(f, "template_poll_ms {} must be at least 100", v)
            }
            ConfigError::InvalidMaxConnections(v) => {
                write!(f, "max_connections {} must be at least 1", v)
            }
            ConfigError::ForgeMissingAuthKey => {
                write!(f, "forge_relay_enabled requires forge_auth_key")
            }
            ConfigError::InvalidFecConfig { data, parity } => {
                write!(f, "FEC config invalid: data={}, parity={} (both must be >= 1)", data, parity)
            }
            ConfigError::JdMissingPayoutScript => {
                write!(f, "jd_listen_addr set but pool_payout_script is missing")
            }
            ConfigError::InvalidTimingJitter { min_ms, max_ms } => {
                write!(
                    f,
                    "timing_jitter_min_ms ({}) must be <= timing_jitter_max_ms ({})",
                    min_ms, max_ms
                )
            }
            ConfigError::InvalidFecShardTotal { total } => {
                write!(
                    f,
                    "FEC shard total {} exceeds Reed-Solomon maximum of 255",
                    total
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl PoolConfig {
    /// Validate the configuration and return any errors
    pub fn validate(&self) -> Result<(), ConfigError> {
        // nonce_1_len must leave room for at least 1 byte of nonce_2
        if self.nonce_1_len == 0 || self.nonce_1_len > 31 {
            return Err(ConfigError::InvalidNonce1Len(self.nonce_1_len));
        }

        // Difficulty must be positive
        if self.initial_difficulty <= 0.0 || !self.initial_difficulty.is_finite() {
            return Err(ConfigError::InvalidDifficulty(self.initial_difficulty));
        }

        // Target shares per minute must be positive
        if self.target_shares_per_minute <= 0.0 || !self.target_shares_per_minute.is_finite() {
            return Err(ConfigError::InvalidTargetSharesPerMinute(
                self.target_shares_per_minute,
            ));
        }

        // Need at least 1 validation thread
        if self.validation_threads == 0 {
            return Err(ConfigError::InvalidValidationThreads(self.validation_threads));
        }

        // Template poll interval should be at least 100ms to avoid hammering Zebra
        if self.template_poll_ms < 100 {
            return Err(ConfigError::InvalidTemplatePollMs(self.template_poll_ms));
        }

        // Need at least 1 connection
        if self.max_connections == 0 {
            return Err(ConfigError::InvalidMaxConnections(self.max_connections));
        }

        // Forge relay requires auth key
        if self.forge_relay_enabled && self.forge_auth_key.is_none() {
            return Err(ConfigError::ForgeMissingAuthKey);
        }

        // FEC shards must be valid
        if self.forge_relay_enabled
            && (self.forge_data_shards == 0 || self.forge_parity_shards == 0)
        {
            return Err(ConfigError::InvalidFecConfig {
                data: self.forge_data_shards,
                parity: self.forge_parity_shards,
            });
        }

        // JD requires payout script
        if self.jd_listen_addr.is_some() && self.pool_payout_script.is_none() {
            return Err(ConfigError::JdMissingPayoutScript);
        }

        // Timing jitter min must not exceed max
        if self.timing_jitter_enabled && self.timing_jitter_min_ms > self.timing_jitter_max_ms {
            return Err(ConfigError::InvalidTimingJitter {
                min_ms: self.timing_jitter_min_ms,
                max_ms: self.timing_jitter_max_ms,
            });
        }

        // FEC shard total must fit in Reed-Solomon's u8 limit
        if self.forge_relay_enabled {
            let total = self.forge_data_shards + self.forge_parity_shards;
            if total > 255 {
                return Err(ConfigError::InvalidFecShardTotal { total });
            }
        }

        Ok(())
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 3333)),
            zebra_url: "http://127.0.0.1:8232".to_string(),
            template_poll_ms: 1000,
            validation_threads: 4,
            nonce_1_len: 4,
            initial_difficulty: 1.0,
            target_shares_per_minute: 5.0,
            max_connections: 10000,
            jd_listen_addr: None, // Disabled by default
            pool_payout_script: None,
            noise_enabled: false,
            noise_private_key_path: None,
            jd_noise_enabled: false,
            jd_full_template_enabled: false,
            jd_full_template_validation: ValidationLevel::Standard,
            jd_min_pool_payout: 0,
            metrics_addr: Some(SocketAddr::from(([127, 0, 0, 1], 9090))),
            json_logging: false,
            otlp_endpoint: None,
            forge_relay_enabled: false,
            forge_bind_addr: Some(SocketAddr::from(([0, 0, 0, 0], 8336))),
            forge_relay_peers: Vec::new(),
            forge_auth_key: None,
            forge_data_shards: 10,
            forge_parity_shards: 3,
            // Security defaults - enable protections by default
            sequence_validation_enabled: true,
            sequence_max_gap: 1000,
            connection_tracking_enabled: true,
            short_lived_threshold_secs: 5,
            max_short_lived_per_window: 10,
            timing_jitter_enabled: false, // Disabled by default for performance
            timing_jitter_min_ms: 0,
            timing_jitter_max_ms: 50,
            warn_plain_mode: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn valid_config() -> PoolConfig {
        PoolConfig::default()
    }

    #[test]
    fn default_config_validates_ok() {
        assert!(valid_config().validate().is_ok());
    }

    // 1. InvalidNonce1Len
    #[test]
    fn nonce1_len_zero_rejected() {
        let mut cfg = valid_config();
        cfg.nonce_1_len = 0;
        assert_eq!(cfg.validate(), Err(ConfigError::InvalidNonce1Len(0)));
    }

    #[test]
    fn nonce1_len_32_rejected() {
        let mut cfg = valid_config();
        cfg.nonce_1_len = 32;
        assert_eq!(cfg.validate(), Err(ConfigError::InvalidNonce1Len(32)));
    }

    #[test]
    fn nonce1_len_1_accepted() {
        let mut cfg = valid_config();
        cfg.nonce_1_len = 1;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn nonce1_len_31_accepted() {
        let mut cfg = valid_config();
        cfg.nonce_1_len = 31;
        assert!(cfg.validate().is_ok());
    }

    // 2. InvalidDifficulty
    #[test]
    fn difficulty_zero_rejected() {
        let mut cfg = valid_config();
        cfg.initial_difficulty = 0.0;
        assert_eq!(cfg.validate(), Err(ConfigError::InvalidDifficulty(0.0)));
    }

    #[test]
    fn difficulty_negative_rejected() {
        let mut cfg = valid_config();
        cfg.initial_difficulty = -1.0;
        assert_eq!(cfg.validate(), Err(ConfigError::InvalidDifficulty(-1.0)));
    }

    #[test]
    fn difficulty_nan_rejected() {
        let mut cfg = valid_config();
        cfg.initial_difficulty = f64::NAN;
        // NaN != NaN, so we match the variant instead
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidDifficulty(_))
        ));
    }

    #[test]
    fn difficulty_infinity_rejected() {
        let mut cfg = valid_config();
        cfg.initial_difficulty = f64::INFINITY;
        assert_eq!(
            cfg.validate(),
            Err(ConfigError::InvalidDifficulty(f64::INFINITY))
        );
    }

    // 3. InvalidTargetSharesPerMinute
    #[test]
    fn target_shares_zero_rejected() {
        let mut cfg = valid_config();
        cfg.target_shares_per_minute = 0.0;
        assert_eq!(
            cfg.validate(),
            Err(ConfigError::InvalidTargetSharesPerMinute(0.0))
        );
    }

    // 4. InvalidValidationThreads
    #[test]
    fn validation_threads_zero_rejected() {
        let mut cfg = valid_config();
        cfg.validation_threads = 0;
        assert_eq!(
            cfg.validate(),
            Err(ConfigError::InvalidValidationThreads(0))
        );
    }

    // 5. InvalidTemplatePollMs
    #[test]
    fn template_poll_99_rejected() {
        let mut cfg = valid_config();
        cfg.template_poll_ms = 99;
        assert_eq!(
            cfg.validate(),
            Err(ConfigError::InvalidTemplatePollMs(99))
        );
    }

    #[test]
    fn template_poll_100_accepted() {
        let mut cfg = valid_config();
        cfg.template_poll_ms = 100;
        assert!(cfg.validate().is_ok());
    }

    // 6. InvalidMaxConnections
    #[test]
    fn max_connections_zero_rejected() {
        let mut cfg = valid_config();
        cfg.max_connections = 0;
        assert_eq!(
            cfg.validate(),
            Err(ConfigError::InvalidMaxConnections(0))
        );
    }

    // 7. ForgeMissingAuthKey
    #[test]
    fn forge_enabled_without_auth_key_rejected() {
        let mut cfg = valid_config();
        cfg.forge_relay_enabled = true;
        cfg.forge_auth_key = None;
        assert_eq!(cfg.validate(), Err(ConfigError::ForgeMissingAuthKey));
    }

    // 8. InvalidFecConfig
    #[test]
    fn forge_zero_data_shards_rejected() {
        let mut cfg = valid_config();
        cfg.forge_relay_enabled = true;
        cfg.forge_auth_key = Some([0u8; 32]);
        cfg.forge_data_shards = 0;
        cfg.forge_parity_shards = 3;
        assert_eq!(
            cfg.validate(),
            Err(ConfigError::InvalidFecConfig {
                data: 0,
                parity: 3
            })
        );
    }

    #[test]
    fn forge_zero_parity_shards_rejected() {
        let mut cfg = valid_config();
        cfg.forge_relay_enabled = true;
        cfg.forge_auth_key = Some([0u8; 32]);
        cfg.forge_data_shards = 10;
        cfg.forge_parity_shards = 0;
        assert_eq!(
            cfg.validate(),
            Err(ConfigError::InvalidFecConfig {
                data: 10,
                parity: 0
            })
        );
    }

    // 9. InvalidFecShardTotal
    #[test]
    fn forge_fec_total_256_rejected() {
        let mut cfg = valid_config();
        cfg.forge_relay_enabled = true;
        cfg.forge_auth_key = Some([0u8; 32]);
        cfg.forge_data_shards = 200;
        cfg.forge_parity_shards = 56;
        assert_eq!(
            cfg.validate(),
            Err(ConfigError::InvalidFecShardTotal { total: 256 })
        );
    }

    #[test]
    fn forge_fec_total_255_accepted() {
        let mut cfg = valid_config();
        cfg.forge_relay_enabled = true;
        cfg.forge_auth_key = Some([0u8; 32]);
        cfg.forge_data_shards = 200;
        cfg.forge_parity_shards = 55;
        assert!(cfg.validate().is_ok());
    }

    // 10. JdMissingPayoutScript
    #[test]
    fn jd_enabled_without_payout_script_rejected() {
        let mut cfg = valid_config();
        cfg.jd_listen_addr = Some(SocketAddr::from(([0, 0, 0, 0], 3334)));
        cfg.pool_payout_script = None;
        assert_eq!(cfg.validate(), Err(ConfigError::JdMissingPayoutScript));
    }

    #[test]
    fn jd_enabled_with_payout_script_accepted() {
        let mut cfg = valid_config();
        cfg.jd_listen_addr = Some(SocketAddr::from(([0, 0, 0, 0], 3334)));
        cfg.pool_payout_script = Some(vec![0x76, 0xa9, 0x14]); // dummy script
        assert!(cfg.validate().is_ok());
    }

    // 11. InvalidTimingJitter
    #[test]
    fn timing_jitter_min_greater_than_max_rejected() {
        let mut cfg = valid_config();
        cfg.timing_jitter_enabled = true;
        cfg.timing_jitter_min_ms = 100;
        cfg.timing_jitter_max_ms = 50;
        assert_eq!(
            cfg.validate(),
            Err(ConfigError::InvalidTimingJitter {
                min_ms: 100,
                max_ms: 50
            })
        );
    }

    #[test]
    fn timing_jitter_min_equals_max_accepted() {
        let mut cfg = valid_config();
        cfg.timing_jitter_enabled = true;
        cfg.timing_jitter_min_ms = 50;
        cfg.timing_jitter_max_ms = 50;
        assert!(cfg.validate().is_ok());
    }

    // 12. Disabled features ignore invalid sub-config
    #[test]
    fn forge_disabled_ignores_missing_auth_key() {
        let mut cfg = valid_config();
        cfg.forge_relay_enabled = false;
        cfg.forge_auth_key = None;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn timing_jitter_disabled_ignores_invalid_range() {
        let mut cfg = valid_config();
        cfg.timing_jitter_enabled = false;
        cfg.timing_jitter_min_ms = 100;
        cfg.timing_jitter_max_ms = 50;
        assert!(cfg.validate().is_ok());
    }
}
