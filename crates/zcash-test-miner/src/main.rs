mod protocol;
mod transport;
mod worker;

use clap::Parser;
use tokio::sync::watch;

use bedrock_noise::PublicKey;
use worker::{run_worker, WorkerConfig};

#[derive(Parser, Debug)]
#[command(name = "zcash-test-miner")]
#[command(about = "CPU Equihash test miner for Bedrock pool testing")]
struct Args {
    /// Pool SV2 endpoint
    #[arg(long, default_value = "127.0.0.1:3333")]
    pool_addr: String,

    /// Number of simulated worker connections
    #[arg(long, default_value = "1")]
    workers: u32,

    /// Worker name prefix (names: {prefix}-1, {prefix}-2, ...)
    #[arg(long, default_value = "worker")]
    worker_prefix: String,

    /// CPU threads per worker for Equihash solving
    #[arg(long, default_value = "1")]
    solver_threads: u32,

    /// Pool's Noise public key (hex). If omitted, connects without encryption.
    #[arg(long)]
    pool_public_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    tracing::info!(
        pool_addr = %args.pool_addr,
        workers = args.workers,
        prefix = %args.worker_prefix,
        solver_threads = args.solver_threads,
        noise = args.pool_public_key.is_some(),
        "Starting zcash-test-miner"
    );

    // Parse the Noise public key if provided
    let server_pubkey = match &args.pool_public_key {
        Some(hex) => {
            let pk = PublicKey::from_hex(hex)?;
            tracing::info!(pubkey = %pk, "Using Noise encryption");
            Some(pk)
        }
        None => {
            tracing::info!("Connecting without Noise encryption");
            None
        }
    };

    // Shutdown signal: sends `true` when Ctrl+C is received
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn worker tasks
    let mut handles = Vec::new();
    for i in 1..=args.workers {
        let config = WorkerConfig {
            pool_addr: args.pool_addr.clone(),
            worker_name: format!("{}-{}", args.worker_prefix, i),
            solver_threads: args.solver_threads,
            server_pubkey: server_pubkey.clone(),
        };
        let rx = shutdown_rx.clone();
        let handle = tokio::spawn(async move {
            run_worker(config, rx).await;
        });
        handles.push(handle);
    }

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    tracing::info!("Ctrl+C received, shutting down...");

    // Send shutdown signal to all workers
    let _ = shutdown_tx.send(true);

    // Wait for all workers to finish
    for handle in handles {
        let _ = handle.await;
    }

    tracing::info!("All workers stopped. Goodbye.");
    Ok(())
}
