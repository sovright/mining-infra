//! Run the pool with a MOCK template provider — no Zebra node required.
//!
//! Purpose: the Z15 bench handshake test. It lets the pool serve a valid
//! synthetic block template so the V1 translation proxy can complete the full
//! `mining.subscribe -> set_difficulty -> mining.authorize -> mining.notify`
//! sequence against a real ASIC, without a synced Zebra RPC endpoint.
//!
//! This is NOT for real mining: the template is static and its block target is
//! the impossible all-zeros target, so no submitted share can ever be a real
//! block. It exercises stratum-dialect compatibility only.
//!
//! Usage: cargo run --release --example run_pool_mock -p zcash-pool-server

use zcash_pool_server::{PoolConfig, PoolServer};
use zcash_template_provider::testutil::{MockZebraRpc, TestTemplateFactory};
use zcash_template_provider::{TemplateProvider, TemplateProviderConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // No tracing_subscriber::fmt::init() here — PoolServer initializes logging
    // internally. (Calling it here is what makes the stock `run_pool` example
    // panic with "a global default trace dispatcher has already been set".)

    let config = PoolConfig {
        listen_addr: "0.0.0.0:3333".parse()?,
        initial_difficulty: 0.0001, // floor difficulty; no real shares expected
        target_shares_per_minute: 5.0,
        nonce_1_len: 4,
        noise_enabled: false,
        warn_plain_mode: false,
        metrics_addr: Some("127.0.0.1:9090".parse()?),
        ..Default::default()
    };

    // Mock RPC that hands back a valid template. The provider's poll loop pops
    // one per tick; once a template is processed, `current_template` stays set
    // even after the queue drains, so the pool keeps serving jobs. We still
    // enqueue a generous supply to keep the log quiet for a long test window.
    let mock = MockZebraRpc::new();
    for _ in 0..7200 {
        mock.enqueue_template(TestTemplateFactory::new().build());
    }

    let tp_config = TemplateProviderConfig {
        poll_interval_ms: config.template_poll_ms,
        ..Default::default()
    };
    let provider = TemplateProvider::with_rpc(tp_config, Box::new(mock));

    println!("=== Zcash Pool Server (MOCK template — no Zebra) ===");
    println!("Listening on: {}", config.listen_addr);
    println!("Initial difficulty: {}", config.initial_difficulty);
    println!("Template source: in-process MockZebraRpc (static synthetic template)");
    println!();

    let server = PoolServer::with_template_provider(config, provider)?;
    server.run().await?;

    Ok(())
}
