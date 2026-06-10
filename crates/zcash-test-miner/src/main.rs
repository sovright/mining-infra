mod metrics;
mod protocol;
mod status;
mod transport;
mod v1_client;
mod worker;

use std::io::IsTerminal;
use std::time::Duration;

use clap::Parser;
use tokio::sync::watch;

use metrics::MinerMetrics;
use sovright_noise::PublicKey;
use status::StartupInfo;
use worker::{WorkerConfig, run_worker};
use zcash_mining_protocol::messages::validate_worker_name;

#[derive(Parser, Debug)]
#[command(name = "zcash-test-miner")]
#[command(about = "CPU Equihash test miner for Sovright pool testing")]
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

    /// Use Stratum V1 (JSON-RPC) instead of V2 (binary)
    #[arg(long)]
    v1: bool,

    /// Live stats panel refresh interval, in seconds.
    #[arg(long, default_value = "10")]
    stats_interval: u64,

    /// Disable ANSI colors (also auto-disabled when stdout is not a TTY).
    #[arg(long)]
    no_color: bool,
}

/// Shorten a hex public key for display: first 8 chars + ellipsis.
fn short_key(hex: &str) -> String {
    if hex.len() > 8 {
        format!("{}\u{2026}", &hex[..8])
    } else {
        hex.to_string()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Validate the prefix early: worker names are "{prefix}-{i}" for i in
    // 1..=workers and the full name must pass protocol validation. Check the
    // LONGEST generated name ("{prefix}-{workers}") so a prefix that only fits
    // low indices can't pass startup and then reconnect-loop forever on a
    // higher-index worker (e.g. a 62-byte prefix where "{prefix}-10" is 65
    // bytes). This also catches forbidden characters in the prefix itself.
    let longest_name = format!("{}-{}", args.worker_prefix, args.workers);
    if let Err(e) = validate_worker_name(&longest_name) {
        eprintln!("Invalid --worker-prefix {:?}: {}", args.worker_prefix, e);
        std::process::exit(1);
    }

    // Color when stdout is an interactive terminal and not explicitly disabled.
    let tty = std::io::stdout().is_terminal();
    let color = tty && !args.no_color;

    // Shared, cumulative metrics feeding the live stats panel.
    let metrics = MinerMetrics::new();

    // Print the launch banner (both modes).
    let mode = if args.v1 { "Stratum V1" } else { "Stratum V2" };
    let encryption = if args.v1 {
        None
    } else {
        args.pool_public_key.as_deref().map(short_key)
    };
    let banner_workers = if args.v1 { 1 } else { args.workers };
    print!(
        "{}",
        status::startup_banner(
            &StartupInfo {
                version: env!("CARGO_PKG_VERSION"),
                mode,
                pool_addr: &args.pool_addr,
                workers: banner_workers,
                solver_threads: args.solver_threads,
                encryption,
            },
            color,
        )
    );

    // Shutdown signal: sends `true` when Ctrl+C is received (or the V1 session
    // ends), used to stop both workers and the stats renderer.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn the live stats renderer.
    let renderer = tokio::spawn(status::run_stats_renderer(
        metrics.clone(),
        Duration::from_secs(args.stats_interval.max(1)),
        color,
        tty,
        shutdown_rx.clone(),
    ));

    if args.v1 {
        let worker_name = format!("{}-1", args.worker_prefix);
        let result = v1_client::run_v1(&args.pool_addr, &worker_name, metrics.clone(), color).await;
        let _ = shutdown_tx.send(true);
        let _ = renderer.await;
        return result;
    }

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

    // Spawn worker tasks
    let mut handles = Vec::new();
    for i in 1..=args.workers {
        let config = WorkerConfig {
            pool_addr: args.pool_addr.clone(),
            worker_name: format!("{}-{}", args.worker_prefix, i),
            solver_threads: args.solver_threads,
            server_pubkey: server_pubkey.clone(),
            color,
        };
        let rx = shutdown_rx.clone();
        let m = metrics.clone();
        let handle = tokio::spawn(async move {
            run_worker(config, m, rx).await;
        });
        handles.push(handle);
    }

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    tracing::info!("Ctrl+C received, shutting down...");

    // Send shutdown signal to all workers and the renderer
    let _ = shutdown_tx.send(true);

    // Wait for all workers to finish
    for handle in handles {
        let _ = handle.await;
    }
    let _ = renderer.await;

    tracing::info!("All workers stopped. Goodbye.");
    Ok(())
}
