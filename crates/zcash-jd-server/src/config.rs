//! JD Server configuration

use std::time::Duration;

use zcash_equihash_validator::difficulty::difficulty_to_target;

use crate::validation::ValidationLevel;

/// JD Server configuration
#[derive(Debug, Clone)]
pub struct JdServerConfig {
    /// Token validity duration
    pub token_lifetime: Duration,

    /// Maximum coinbase output size miners can add (bytes)
    pub coinbase_output_max_additional_size: u32,

    /// Pool's payout script (for coinbase output)
    pub pool_payout_script: Vec<u8>,

    /// Allow async mining (start mining before job acknowledged)
    pub async_mining_allowed: bool,

    /// Maximum active tokens per client
    pub max_tokens_per_client: usize,

    /// Enable Noise encryption for JD client connections
    pub noise_enabled: bool,

    /// Enable Full-Template mode (in addition to Coinbase-Only)
    pub full_template_enabled: bool,

    /// Validation level for full templates
    pub full_template_validation: ValidationLevel,

    /// Minimum pool payout value (zatoshis) for full templates
    pub min_pool_payout: u64,

    /// Pool-granted share target for declared jobs (little-endian, matching
    /// `Target::to_le_bytes`).
    ///
    /// The pool chooses this (never the client) so fake-easy shares cannot
    /// inflate payout credit. It is granted at declaration time, returned in
    /// `SetCustomMiningJobSuccess`, and stored in the job for share validation.
    ///
    /// The default is derived via
    /// `zcash_equihash_validator::difficulty::difficulty_to_target` from a
    /// difficulty of 0.0001, which matches the testnet example configs'
    /// `initial_difficulty`. There is no shared constant linking the JD and
    /// stratum systems — the stratum DEFAULT `initial_difficulty` is 1.0
    /// (`zcash-pool-server/src/config.rs`), and 0.0001 appears only in the
    /// testnet example binaries.
    ///
    /// Note: `difficulty_to_target(0.0001)` clamps to all-ones (`[0xff; 32]`)
    /// because difficulty < 1.0 (see `difficulty.rs`), so the DEFAULT accepts
    /// any valid Equihash solution. Production configs MUST set a real target.
    pub share_target: [u8; 32],
}

/// The default difficulty used to derive the JD share target.
///
/// Matches the testnet example configs' `initial_difficulty` (0.0001); there is
/// no shared constant linking the JD and stratum systems (the stratum DEFAULT is
/// 1.0). Because 0.0001 < 1.0, the derived target clamps to all-ones and accepts
/// any valid Equihash solution — production configs must override it. See
/// [`JdServerConfig::share_target`].
const DEFAULT_SHARE_DIFFICULTY: f64 = 0.0001;

impl Default for JdServerConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Duration::from_secs(300), // 5 minutes
            coinbase_output_max_additional_size: 256,
            pool_payout_script: vec![], // Must be set by operator
            async_mining_allowed: true,
            max_tokens_per_client: 10,
            noise_enabled: false,
            full_template_enabled: false,
            full_template_validation: ValidationLevel::Standard,
            min_pool_payout: 0,
            share_target: difficulty_to_target(DEFAULT_SHARE_DIFFICULTY).0,
        }
    }
}
