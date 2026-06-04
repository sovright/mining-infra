mod config;
mod session;
mod translate;
mod v1;

use clap::Parser;
use config::ProxyConfig;
use session::{MinerSession, ProxyMetrics};
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use v1::codec::V1Codec;

#[derive(Parser, Debug)]
#[command(name = "sovright-v1-stratum-proxy")]
#[command(about = "Stratum V1 to Sovright V2 translation proxy")]
struct Args {
    #[arg(long, short = 'c')]
    config: Option<PathBuf>,

    #[arg(long)]
    listen: Option<SocketAddr>,

    #[arg(long)]
    upstream: Option<SocketAddr>,

    #[arg(long)]
    upstream_connect_timeout_secs: Option<u64>,

    #[arg(long)]
    upstream_reconnect_max_secs: Option<u64>,

    #[arg(long)]
    miner_idle_timeout_secs: Option<u64>,

    #[arg(long)]
    metrics_enabled: bool,

    #[arg(long)]
    no_metrics: bool,

    #[arg(long)]
    metrics_listen: Option<SocketAddr>,

    #[arg(long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();
    let mut config = if let Some(path) = &args.config {
        ProxyConfig::from_file(path)?
    } else {
        ProxyConfig::default()
    };

    let metrics_enabled = if args.metrics_enabled {
        Some(true)
    } else if args.no_metrics {
        Some(false)
    } else {
        None
    };

    config.apply_overrides(
        args.listen,
        args.upstream,
        args.upstream_connect_timeout_secs,
        args.upstream_reconnect_max_secs,
        args.miner_idle_timeout_secs,
        metrics_enabled,
        args.metrics_listen,
        args.log_level,
    );

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(config.logging.level.clone())),
        )
        .init();
    let _ = V1Codec::new();

    let listener = TcpListener::bind(config.listen).await?;
    let metrics = Arc::new(ProxyMetrics::default());

    if config.metrics.enabled {
        let metrics_listener = TcpListener::bind(config.metrics.listen).await?;
        tokio::spawn(run_metrics_server(metrics_listener, Arc::clone(&metrics)));
        info!(listen = %config.metrics.listen, "Metrics endpoint enabled");
    }

    info!(
        listen = %config.listen,
        upstream = %config.upstream,
        "Stratum V1 translation proxy listening"
    );

    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, peer_addr) = accept_result?;
                let session_config = config.clone();
                let session_metrics = Arc::clone(&metrics);
                session_metrics.on_session_started();
                sessions.spawn(async move {
                    let result = run_session(stream, peer_addr, session_config, Arc::clone(&session_metrics)).await;
                    session_metrics.on_session_stopped();
                    result
                });
            }
            maybe_joined = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(joined) = maybe_joined {
                    match joined {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => warn!("Session ended with error: {}", error),
                        Err(error) => warn!("Session task failed: {}", error),
                    }
                }
            }
            shutdown = shutdown_signal() => {
                shutdown?;
                info!("Shutdown signal received, stopping listener");
                break;
            }
        }
    }

    let drain = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(joined) = sessions.join_next().await {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!("Session ended with error during shutdown: {}", error),
                Err(error) => warn!("Session task failed during shutdown: {}", error),
            }
        }
    })
    .await;

    if drain.is_err() {
        warn!("Timed out draining sessions, aborting remaining tasks");
        sessions.abort_all();
        while sessions.join_next().await.is_some() {}
    }

    Ok(())
}

async fn run_session(
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: ProxyConfig,
    metrics: Arc<ProxyMetrics>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let session = MinerSession::new(stream, config, metrics, peer_addr);
    session.run().await.map_err(|error| Box::new(error) as _)
}

async fn run_metrics_server(listener: TcpListener, metrics: Arc<ProxyMetrics>) {
    loop {
        match listener.accept().await {
            Ok((mut stream, peer_addr)) => {
                let metrics = Arc::clone(&metrics);
                tokio::spawn(async move {
                    if let Err(error) = serve_metrics(&mut stream, metrics).await {
                        warn!(peer = %peer_addr, "Metrics request failed: {}", error);
                    }
                });
            }
            Err(error) => {
                error!("Metrics listener error: {}", error);
                break;
            }
        }
    }
}

async fn serve_metrics(
    stream: &mut TcpStream,
    metrics: Arc<ProxyMetrics>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut request_buf = [0u8; 1024];
    let _ = stream.read(&mut request_buf).await?;

    let body = metrics.render_prometheus();
    let response = format!(
        concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/plain; version=0.0.4\r\n",
            "Content-Length: {}\r\n",
            "Connection: close\r\n",
            "\r\n",
            "{}"
        ),
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn shutdown_signal() -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
            }
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }

    Ok(())
}
