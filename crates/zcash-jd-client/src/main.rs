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

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the env-var → flag contract the sovereignty bundle relies on.
    ///
    /// All assertions live in a single test so the env mutations cannot race
    /// other tests (cargo runs tests in parallel by default). Env vars are
    /// restored at the end regardless of assertion outcome.
    #[test]
    fn env_vars_drive_config_and_flags_win() {
        let keys = [
            "ZEBRA_RPC",
            "POOL_SV2_ENDPOINT",
            "ACCOUNT_ID",
            "JDC_LISTEN",
            "JDC_POLICY",
        ];

        // Save originals.
        let saved: Vec<Option<String>> = keys.iter().map(|k| std::env::var(k).ok()).collect();

        let zebra_env = "http://10.0.0.1:8232";
        let pool_env = "10.0.0.2:3334";
        let account_env = "miner-from-env";
        let listen_env = "127.0.0.1:34255";
        let policy_env = "/etc/jdc/policy.toml";

        unsafe {
            std::env::set_var("ZEBRA_RPC", zebra_env);
            std::env::set_var("POOL_SV2_ENDPOINT", pool_env);
            std::env::set_var("ACCOUNT_ID", account_env);
            std::env::set_var("JDC_LISTEN", listen_env);
            std::env::set_var("JDC_POLICY", policy_env);
        }

        // No CLI flags — every value comes from the environment.
        let args = Args::try_parse_from(["zcash-jd-client"]).unwrap();
        assert_eq!(args.zebra_url, zebra_env, "zebra_url from ZEBRA_RPC");
        assert_eq!(
            args.pool_jd_addr, pool_env,
            "pool_jd_addr from POOL_SV2_ENDPOINT"
        );
        assert_eq!(args.user_id, account_env, "user_id from ACCOUNT_ID");
        assert_eq!(
            args.jdc_listen,
            Some(listen_env.parse().unwrap()),
            "jdc_listen from JDC_LISTEN"
        );
        assert_eq!(
            args.policy.as_deref(),
            Some(std::path::Path::new(policy_env)),
            "policy from JDC_POLICY"
        );

        // CLI flags given AND env set — flags win.
        let zebra_cli = "http://192.168.1.1:8232";
        let pool_cli = "192.168.1.2:3334";
        let account_cli = "miner-from-flag";
        let listen_cli = "127.0.0.1:44255";
        let policy_cli = "/tmp/override-policy.toml";
        let args = Args::try_parse_from([
            "zcash-jd-client",
            "--zebra-url",
            zebra_cli,
            "--pool-jd-addr",
            pool_cli,
            "--user-id",
            account_cli,
            "--jdc-listen",
            listen_cli,
            "--policy",
            policy_cli,
        ])
        .unwrap();
        assert_eq!(args.zebra_url, zebra_cli, "--zebra-url beats ZEBRA_RPC");
        assert_eq!(
            args.pool_jd_addr, pool_cli,
            "--pool-jd-addr beats POOL_SV2_ENDPOINT"
        );
        assert_eq!(args.user_id, account_cli, "--user-id beats ACCOUNT_ID");
        assert_eq!(
            args.jdc_listen,
            Some(listen_cli.parse().unwrap()),
            "--jdc-listen beats JDC_LISTEN"
        );
        assert_eq!(
            args.policy.as_deref(),
            Some(std::path::Path::new(policy_cli)),
            "--policy beats JDC_POLICY"
        );

        // Restore originals.
        unsafe {
            for (k, v) in keys.iter().zip(saved) {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }
}
