use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{env, fs};

use bedrock_forge::{RelayConfig, RelayNode, render_prometheus_text};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("bedrock_forge=info".parse()?),
        )
        .init();

    let config = config_from_env()?;
    let mut node = RelayNode::new(config)?;
    node.bind().await?;

    let local_addr = node
        .local_addr()
        .ok_or("relay node did not report a bound local address")?;
    info!(%local_addr, "Bedrock FORGE relay listening");

    let node = Arc::new(node);
    let metrics_node = Arc::clone(&node);
    let metrics_textfile = env::var_os("BEDROCK_FORGE_METRICS_TEXTFILE").map(PathBuf::from);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let snapshot = metrics_node.metrics().snapshot();
            let sessions = metrics_node.session_count().await;
            info!(
                sessions,
                packets_received = snapshot.packets_received,
                packets_forwarded = snapshot.packets_forwarded,
                auth_failures = snapshot.auth_failures,
                invalid_chunks = snapshot.invalid_chunks,
                sessions_created = snapshot.sessions_created,
                sessions_expired = snapshot.sessions_expired,
                "FORGE relay metrics"
            );
            if let Some(path) = &metrics_textfile {
                let text = render_prometheus_text(&snapshot, sessions);
                if let Err(error) = write_metrics_textfile(path, &text) {
                    warn!(%error, path = %path.display(), "Failed to write FORGE relay metrics textfile");
                }
            }
        }
    });

    node.run().await?;
    Ok(())
}

fn config_from_env() -> Result<RelayConfig, Box<dyn std::error::Error + Send + Sync>> {
    let listen_addr: SocketAddr = env::var("BEDROCK_FORGE_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8333".to_string())
        .parse()?;
    let mut config = RelayConfig::new(listen_addr);
    let default_data_shards = config.data_shards;
    let default_parity_shards = config.parity_shards;
    let default_session_timeout_secs = config.session_timeout.as_secs();
    let default_assembly_timeout_secs = config.assembly_timeout.as_secs();
    let default_max_sessions = config.max_sessions;
    let default_chunk_size = config.chunk_size;

    let auth_keys = auth_keys_from_env()?;
    let allow_unauthenticated = env_bool("BEDROCK_FORGE_ALLOW_UNAUTHENTICATED", false)?;
    config = config
        .with_authorized_keys(auth_keys)
        .with_unauthenticated_peers_allowed(allow_unauthenticated)
        .with_fec(
            env_usize("BEDROCK_FORGE_DATA_SHARDS", default_data_shards)?,
            env_usize("BEDROCK_FORGE_PARITY_SHARDS", default_parity_shards)?,
        )
        .with_timeouts(
            Duration::from_secs(env_u64(
                "BEDROCK_FORGE_SESSION_TIMEOUT_SECS",
                default_session_timeout_secs,
            )?),
            Duration::from_secs(env_u64(
                "BEDROCK_FORGE_ASSEMBLY_TIMEOUT_SECS",
                default_assembly_timeout_secs,
            )?),
        )
        .with_max_sessions(env_usize(
            "BEDROCK_FORGE_MAX_SESSIONS",
            default_max_sessions,
        )?);
    config.chunk_size = env_usize("BEDROCK_FORGE_CHUNK_SIZE", default_chunk_size)?;

    Ok(config)
}

fn auth_keys_from_env() -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
    let mut values = Vec::new();
    if let Ok(value) = env::var("BEDROCK_FORGE_AUTH_KEY_HEX") {
        values.push(value);
    }
    if let Ok(value) = env::var("BEDROCK_FORGE_AUTH_KEYS_HEX") {
        values.extend(value.split(',').map(str::to_owned));
    }

    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| parse_auth_key(&value))
        .collect()
}

fn parse_auth_key(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    if value.is_empty() {
        return Err("empty auth key".into());
    }
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        return Err(format!("auth key must be 32 bytes, got {}", bytes.len()).into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn env_bool(name: &str, default: bool) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    match env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(format!("invalid boolean {name}: {value}").into()),
        },
        Err(_) => Ok(default),
    }
}

fn env_usize(
    name: &str,
    default: usize,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(_) => Ok(default),
    }
}

fn env_u64(name: &str, default: u64) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(_) => Ok(default),
    }
}

fn write_metrics_textfile(
    path: &Path,
    text: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension(format!(
        "{}.tmp.{}",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("prom"),
        std::process::id()
    ));
    fs::write(&tmp_path, text)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn write_metrics_textfile_creates_parent_and_replaces_contents() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = env::temp_dir().join(format!(
            "bedrock-forge-relay-metrics-test-{}-{suffix}",
            std::process::id()
        ));
        let path = dir.join("metrics.prom");

        write_metrics_textfile(&path, "old_metric 1\n").unwrap();
        write_metrics_textfile(&path, "new_metric 2\n").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "new_metric 2\n");
        fs::remove_dir_all(&dir).unwrap();
    }
}
