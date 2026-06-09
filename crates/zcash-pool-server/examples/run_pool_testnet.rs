//! Run a pool server against Zebra testnet
//!
//! Usage: cargo run --example run_pool_testnet -p zcash-pool-server
//!
//! Requires a Zebra node running on testnet with RPC enabled on port 18232.
//! See testnet/zebrad.toml for the recommended Zebra configuration.
//!
//! Optional env vars (must be set together to enable JD):
//!   JD_LISTEN_ADDR               e.g. 0.0.0.0:34264
//!   JD_POOL_PAYOUT_SCRIPT_HEX    hex-encoded P2PKH script for pool payouts

use zcash_pool_server::{PoolConfig, PoolServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // JD (Job Declaration) is opt-in: both env vars must be set together.
    // PoolConfig::validate() additionally enforces the payout-script pairing
    // (ConfigError::JdMissingPayoutScript), but we parse here so a typo'd
    // value fails loudly instead of half-configuring the server.
    let jd_listen_env = std::env::var("JD_LISTEN_ADDR").ok();
    let jd_script_env = std::env::var("JD_POOL_PAYOUT_SCRIPT_HEX").ok();
    let (jd_listen_addr, pool_payout_script) = match (jd_listen_env, jd_script_env) {
        (Some(addr), Some(script_hex)) => {
            let addr: std::net::SocketAddr = addr
                .parse()
                .map_err(|e| format!("invalid JD_LISTEN_ADDR '{addr}': {e}"))?;
            let script = hex::decode(script_hex.trim())
                .map_err(|e| format!("invalid JD_POOL_PAYOUT_SCRIPT_HEX: {e}"))?;
            if script.is_empty() {
                return Err("JD_POOL_PAYOUT_SCRIPT_HEX must not be empty".into());
            }
            (Some(addr), Some(script))
        }
        (None, None) => (None, None),
        _ => {
            return Err("JD_LISTEN_ADDR and JD_POOL_PAYOUT_SCRIPT_HEX must be set together".into());
        }
    };

    let config = PoolConfig {
        listen_addr: "0.0.0.0:3333".parse()?,
        zebra_url: "http://127.0.0.1:18232".to_string(),
        initial_difficulty: 1e-9, // below the all-ones saturation point (max_target/2^256): accept every valid solution at cold start; vardiff ramps up from there
        target_shares_per_minute: 5.0,
        nonce_1_len: 4,
        noise_enabled: false,
        warn_plain_mode: false, // suppress warning for testnet
        metrics_addr: Some("127.0.0.1:9090".parse()?),
        jd_listen_addr,
        pool_payout_script,
        ..Default::default()
    };

    println!("=== Zcash Pool Server (Testnet) ===");
    println!("Listening on: {}", config.listen_addr);
    println!("Zebra RPC: {}", config.zebra_url);
    println!("Prometheus: {:?}", config.metrics_addr);
    println!("Nonce_1 length: {} bytes", config.nonce_1_len);
    println!("Initial difficulty: {}", config.initial_difficulty);
    match config.jd_listen_addr {
        Some(addr) => println!("JD Server: enabled on {addr}"),
        None => println!(
            "JD Server: disabled (set JD_LISTEN_ADDR + JD_POOL_PAYOUT_SCRIPT_HEX to enable)"
        ),
    }
    println!();

    let server = PoolServer::new(config)?;
    server.run().await?;

    Ok(())
}
