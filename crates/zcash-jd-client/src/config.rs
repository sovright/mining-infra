//! JD Client configuration

use std::net::SocketAddr;

/// Transaction selection strategy for Full-Template mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TxSelectionStrategy {
    /// Include all transactions from template (default)
    #[default]
    All,
    /// Prioritize by fee rate
    ByFeeRate,
}

impl TxSelectionStrategy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "all" => Some(Self::All),
            "by-fee-rate" | "byfee" | "fee" => Some(Self::ByFeeRate),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::ByFeeRate => "by-fee-rate",
        }
    }
}

impl std::fmt::Display for TxSelectionStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for TxSelectionStrategy {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}

#[derive(Debug, Clone)]
pub struct JdClientConfig {
    pub zebra_url: String,
    pub pool_jd_addr: SocketAddr,
    pub user_identifier: String,
    pub template_poll_ms: u64,
    pub miner_payout_address: Option<String>,
    /// Enable Noise encryption
    pub noise_enabled: bool,
    /// Pool's Noise public key (hex-encoded, required if noise_enabled)
    pub pool_public_key: Option<String>,
    /// Use Full-Template mode (requires local transaction selection)
    pub full_template_mode: bool,
    /// Transaction selection strategy for Full-Template mode
    pub tx_selection: TxSelectionStrategy,
    /// Address to bind the downstream listener on (serves declared jobs to the
    /// translator proxy). `None` disables the listener.
    pub jdc_listen: Option<SocketAddr>,
}

impl Default for JdClientConfig {
    fn default() -> Self {
        Self {
            zebra_url: "http://127.0.0.1:8232".to_string(),
            pool_jd_addr: "127.0.0.1:3334".parse().unwrap(),
            user_identifier: "zcash-jd-client".to_string(),
            template_poll_ms: 1000,
            miner_payout_address: None,
            noise_enabled: false,
            pool_public_key: None,
            full_template_mode: false,
            tx_selection: TxSelectionStrategy::All,
            jdc_listen: None,
        }
    }
}
