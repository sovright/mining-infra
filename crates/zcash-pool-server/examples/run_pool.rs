//! Run a basic pool server
//!
//! Usage: cargo run --example run_pool -p zcash-pool-server

use zcash_pool_server::{PoolConfig, PoolServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let mut config = PoolConfig {
        listen_addr: "127.0.0.1:3333".parse()?,
        zebra_url: "http://127.0.0.1:8232".to_string(),
        ..Default::default()
    };

    // Relay configuration (optional)
    // Enable for low-latency block propagation to relay network.
    // When enabled, the pool will broadcast newly found blocks to relay peers
    // using UDP with forward error correction (FEC) for fast, reliable delivery.
    config.relay_enabled = false; // Set to true to enable
    config.relay_peers = vec![
        // Add relay peer addresses here, e.g.:
        // "relay1.example.com:8336".parse().unwrap(),
        // "relay2.example.com:8336".parse().unwrap(),
    ];
    // Optional: bind address for receiving relay messages (default: 0.0.0.0:8336)
    // config.relay_bind_addr = Some("0.0.0.0:8336".parse().unwrap());
    // Optional: shared authentication key with relay peers (32 bytes)
    // config.relay_auth_key = Some([0x42; 32]);
    // FEC parameters: data_shards + parity_shards = total shards sent
    // More parity shards = better recovery from packet loss, but more bandwidth
    config.relay_data_shards = 10;
    config.relay_parity_shards = 3;

    println!("=== Zcash Pool Server ===");
    println!("Listening on: {}", config.listen_addr);
    println!("Zebra RPC: {}", config.zebra_url);
    println!("Nonce_1 length: {} bytes", config.nonce_1_len);
    println!("Initial difficulty: {}", config.initial_difficulty);
    println!();

    let server = PoolServer::new(config)?;
    server.run().await?;

    Ok(())
}
