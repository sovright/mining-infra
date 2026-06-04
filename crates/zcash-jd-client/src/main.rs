//! Zcash JD Client binary

use std::path::PathBuf;

use clap::Parser;
use tracing::{info, warn};
use zcash_jd_client::policy::{CONVENTIONAL_POLICY_PATH, load_policy, resolve_policy_path};
use zcash_jd_client::{JdClient, JdClientConfig, config::TxSelectionStrategy};

#[derive(Parser, Debug)]
#[command(name = "zcash-jd-client")]
#[command(about = "Zcash Job Declaration Client for Stratum V2")]
struct Args {
    /// Zebra RPC URL
    #[arg(long, default_value = "http://127.0.0.1:8232", env = "ZEBRA_RPC")]
    zebra_url: String,

    /// Pool JD Server address
    #[arg(long, default_value = "127.0.0.1:3334", env = "POOL_SV2_ENDPOINT")]
    pool_jd_addr: String,

    /// User identifier for job allocation
    #[arg(long, default_value = "zcash-jd-client", env = "ACCOUNT_ID")]
    user_id: String,

    /// Template polling interval in milliseconds
    #[arg(long, default_value = "1000")]
    poll_interval: u64,

    /// Optional miner payout address
    #[arg(long)]
    payout_address: Option<String>,

    /// Enable Noise encryption
    #[arg(long)]
    noise: bool,

    /// Pool's Noise public key (hex-encoded)
    #[arg(long)]
    pool_public_key: Option<String>,

    /// Use Full-Template mode for transaction selection
    #[arg(long)]
    full_template: bool,

    /// Transaction selection strategy (all, by-fee-rate)
    #[arg(long, default_value = "all")]
    tx_selection: String,

    /// Bind address for the downstream listener that serves declared jobs to
    /// the translator proxy (e.g. 127.0.0.1:34255). Omit to disable.
    #[arg(long, env = "JDC_LISTEN")]
    jdc_listen: Option<std::net::SocketAddr>,

    /// Path to the censorship-policy file (TOML).  If omitted, the
    /// conventional container path /etc/jdc/policy.toml is probed; if that
    /// also does not exist, the client starts with no policy (unchanged
    /// behaviour).
    #[arg(long, env = "JDC_POLICY")]
    policy: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Resolve and load censorship policy (refuse-to-start on any error).
    let conventional = std::path::Path::new(CONVENTIONAL_POLICY_PATH);
    if let Some(policy_path) = resolve_policy_path(args.policy.as_deref(), conventional) {
        match load_policy(&policy_path) {
            Ok(policy) => {
                info!(
                    "Censorship policy loaded from {}: mode = include-all",
                    policy_path.display()
                );
                for section in &policy.deferred_warnings {
                    warn!(
                        "policy section '{}' present but not yet enforced — deferred",
                        section
                    );
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }

    let config = JdClientConfig {
        zebra_url: args.zebra_url,
        pool_jd_addr: args.pool_jd_addr.parse()?,
        user_identifier: args.user_id,
        template_poll_ms: args.poll_interval,
        miner_payout_address: args.payout_address,
        noise_enabled: args.noise,
        pool_public_key: args.pool_public_key,
        full_template_mode: args.full_template,
        tx_selection: TxSelectionStrategy::parse(&args.tx_selection)
            .unwrap_or(TxSelectionStrategy::All),
        jdc_listen: args.jdc_listen,
    };

    info!("=== Zcash JD Client ===");
    info!("Zebra RPC: {}", config.zebra_url);
    info!("Pool JD Server: {}", config.pool_jd_addr);
    info!("User ID: {}", config.user_identifier);
    info!("Poll interval: {}ms", config.template_poll_ms);
    info!(
        "Noise encryption: {}",
        if config.noise_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    if config.full_template_mode {
        info!(
            "Full-Template mode: enabled (tx selection: {})",
            config.tx_selection
        );
    } else {
        info!("Full-Template mode: disabled (using Coinbase-Only)");
    }
    match config.jdc_listen {
        Some(addr) => info!("Downstream listener: {}", addr),
        None => info!("Downstream listener: disabled (use --jdc-listen to enable)"),
    }

    let client = JdClient::new(config)?;
    client.run().await?;

    Ok(())
}
