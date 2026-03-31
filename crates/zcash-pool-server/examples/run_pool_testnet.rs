//! Run a pool server against Zebra testnet
//!
//! Usage: cargo run --example run_pool_testnet -p zcash-pool-server
//!
//! Requires a Zebra node running on testnet with RPC enabled on port 18232.
//! See testnet/zebrad.toml for the recommended Zebra configuration.

use zcash_pool_server::{PoolConfig, PoolServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let config = PoolConfig {
        listen_addr: "0.0.0.0:3333".parse()?,
        zebra_url: "http://127.0.0.1:18232".to_string(),
        initial_difficulty: 1.0,
        target_shares_per_minute: 5.0,
        nonce_1_len: 4,
        noise_enabled: false,
        warn_plain_mode: false, // suppress warning for testnet
        metrics_addr: Some("127.0.0.1:9090".parse()?),
        ..Default::default()
    };

    println!("=== Zcash Pool Server (Testnet) ===");
    println!("Listening on: {}", config.listen_addr);
    println!("Zebra RPC: {}", config.zebra_url);
    println!("Prometheus: {:?}", config.metrics_addr);
    println!("Nonce_1 length: {} bytes", config.nonce_1_len);
    println!("Initial difficulty: {}", config.initial_difficulty);
    println!();

    let server = PoolServer::new(config)?;
    server.run().await?;

    Ok(())
}
