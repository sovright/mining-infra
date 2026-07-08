use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{env, fs};

use sovright_relay::{ArrivalSink, AuthKey, RelayConfig, RelayNode, render_prometheus_text};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sovright_relay=info".parse()?),
        )
        .init();

    let config = config_from_env()?;
    let mut node = RelayNode::new(config)?;
    if let Some(path) = env::var_os("SOVRIGHT_RELAY_ARRIVAL_LOG") {
        let path = PathBuf::from(path);
        info!(path = %path.display(), "Relay block-arrival logging enabled");
        node = node.with_arrival_sink(Some(ArrivalSink::new(&path)?));
    }
    node.bind().await?;

    let local_addr = node
        .local_addr()
        .ok_or("relay node did not report a bound local address")?;
    info!(%local_addr, "Sovright relay listening");

    let node = Arc::new(node);
    let metrics_node = Arc::clone(&node);
    let metrics_textfile = env::var_os("SOVRIGHT_RELAY_METRICS_TEXTFILE").map(PathBuf::from);
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
                socket_receive_errors = snapshot.socket_receive_errors,
                packet_send_errors = snapshot.packet_send_errors,
                forward_no_peer_chunks = snapshot.forward_no_peer_chunks,
                compact_block_chunks_received = snapshot.compact_block_chunks_received,
                compact_block_chunks_forwarded = snapshot.compact_block_chunks_forwarded,
                raw_segment_chunks_received = snapshot.raw_segment_chunks_received,
                raw_segment_chunks_forwarded = snapshot.raw_segment_chunks_forwarded,
                raw_segment_duplicate_chunks = snapshot.raw_segment_duplicate_chunks,
                raw_segment_validation_deferred = snapshot.raw_segment_validation_deferred,
                raw_segment_validation_successes = snapshot.raw_segment_validation_successes,
                raw_segment_validation_failures = snapshot.raw_segment_validation_failures,
                raw_segment_cached_promotions = snapshot.raw_segment_cached_promotions,
                auth_failures = snapshot.auth_failures,
                invalid_chunks = snapshot.invalid_chunks,
                sessions_created = snapshot.sessions_created,
                sessions_expired = snapshot.sessions_expired,
                session_limit_rejections = snapshot.session_limit_rejections,
                "Sovright relay metrics"
            );
            if let Some(path) = &metrics_textfile {
                let text = render_prometheus_text(&snapshot, sessions);
                if let Err(error) = write_metrics_textfile(path, &text) {
                    warn!(%error, path = %path.display(), "Failed to write Sovright relay metrics textfile");
                }
            }
        }
    });

    node.run().await?;
    Ok(())
}

fn config_from_env() -> Result<RelayConfig, Box<dyn std::error::Error + Send + Sync>> {
    let listen_addr: SocketAddr = env::var("SOVRIGHT_RELAY_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8333".to_string())
        .parse()?;
    let mut config = RelayConfig::new(listen_addr);
    let default_data_shards = config.data_shards;
    let default_parity_shards = config.parity_shards;
    let default_session_timeout_secs = config.session_timeout.as_secs();
    let default_assembly_timeout_secs = config.assembly_timeout.as_secs();
    let default_max_sessions = config.max_sessions;
    let default_chunk_size = config.chunk_size;
    let default_forward_burst_packets = config.forward_burst_packets;
    let default_forward_burst_delay_micros = micros_from_duration(config.forward_burst_delay)?;

    let auth_keys = auth_keys_from_env()?;
    require_auth_keys(&auth_keys)?;
    config = config
        .with_authorized_keys(auth_keys)
        .with_fec(
            env_usize("SOVRIGHT_RELAY_DATA_SHARDS", default_data_shards)?,
            env_usize("SOVRIGHT_RELAY_PARITY_SHARDS", default_parity_shards)?,
        )
        .with_timeouts(
            Duration::from_secs(env_u64(
                "SOVRIGHT_RELAY_SESSION_TIMEOUT_SECS",
                default_session_timeout_secs,
            )?),
            Duration::from_secs(env_u64(
                "SOVRIGHT_RELAY_ASSEMBLY_TIMEOUT_SECS",
                default_assembly_timeout_secs,
            )?),
        )
        .with_max_sessions(env_usize(
            "SOVRIGHT_RELAY_MAX_SESSIONS",
            default_max_sessions,
        )?)
        .with_forward_pacing(
            env_usize(
                "SOVRIGHT_RELAY_FORWARD_BURST_PACKETS",
                default_forward_burst_packets,
            )?,
            Duration::from_micros(env_u64(
                "SOVRIGHT_RELAY_FORWARD_BURST_DELAY_MICROS",
                default_forward_burst_delay_micros,
            )?),
        );
    config.chunk_size = env_usize("SOVRIGHT_RELAY_CHUNK_SIZE", default_chunk_size)?;

    Ok(config)
}

/// Sentinel key id reserved for unauthenticated sessions. Must stay in sync
/// with `relay::node::UNAUTHENTICATED_KEY_ID` (that const is private to the
/// library, so it cannot be imported here). No operator-configured auth key
/// may use this id, or it would collide with the unauthenticated-session
/// sentinel.
const RESERVED_UNAUTHENTICATED_KEY_ID: &str = "unauthenticated";

/// Identity label allowed for a configured auth key: `[A-Za-z0-9_-]{1,32}`,
/// excluding the reserved unauthenticated-session sentinel.
fn is_valid_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id != RESERVED_UNAUTHENTICATED_KEY_ID
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Parse the relay's configured auth keys.
///
/// `SOVRIGHT_RELAY_AUTH_KEY_HEX` (singular) is the fleet key by convention
/// and is always given the id `fleet`.
///
/// `SOVRIGHT_RELAY_AUTH_KEYS_HEX` is a comma-separated list where each entry
/// is either `id:hex64` (an explicitly labeled per-invitee key) or a bare
/// `hex64` (back-compat; an id is derived as `key<index>`, `index` being the
/// entry's 0-based position in the list).
///
/// Every id must match `[A-Za-z0-9_-]{1,32}` and must be unique across both
/// env vars combined -- both are startup errors, never silently resolved.
fn auth_keys_from_env() -> Result<Vec<AuthKey>, Box<dyn std::error::Error + Send + Sync>> {
    let mut keys: Vec<AuthKey> = Vec::new();

    if let Ok(value) = env::var("SOVRIGHT_RELAY_AUTH_KEY_HEX") {
        let value = value.trim();
        if !value.is_empty() {
            keys.push(AuthKey::new("fleet", parse_auth_key(value)?));
        }
    }

    if let Ok(value) = env::var("SOVRIGHT_RELAY_AUTH_KEYS_HEX") {
        for (index, entry) in value.split(',').enumerate() {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            keys.push(parse_named_auth_key(entry, index)?);
        }
    }

    require_unique_key_ids(&keys)?;

    Ok(keys)
}

/// Parse one `SOVRIGHT_RELAY_AUTH_KEYS_HEX` entry: `id:hex64` or bare `hex64`.
fn parse_named_auth_key(
    entry: &str,
    index: usize,
) -> Result<AuthKey, Box<dyn std::error::Error + Send + Sync>> {
    match entry.rsplit_once(':') {
        Some((id, hex)) => {
            if !is_valid_key_id(id) {
                return Err(format!(
                    "invalid auth key id '{id}': must match [A-Za-z0-9_-]{{1,32}}"
                )
                .into());
            }
            Ok(AuthKey::new(id, parse_auth_key(hex)?))
        }
        None => Ok(AuthKey::new(format!("key{index}"), parse_auth_key(entry)?)),
    }
}

fn require_unique_key_ids(
    keys: &[AuthKey],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut seen = std::collections::HashSet::new();
    for key in keys {
        if !seen.insert(key.id.as_str()) {
            return Err(format!("duplicate auth key id '{}'", key.id).into());
        }
    }
    Ok(())
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

/// Fail loud at startup if no relay auth key was configured.
///
/// PR-0 removed the unauthenticated, no-HMAC version-1 wire format entirely.
/// There is no more "unauthenticated mode" for this binary to fall back
/// into: previously `SOVRIGHT_RELAY_ALLOW_UNAUTHENTICATED=true` let the relay
/// start and run key-less; that escape hatch has been removed from this
/// binary, so a missing key is now always a hard startup error.
fn require_auth_keys(keys: &[AuthKey]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if keys.is_empty() {
        return Err("relay auth key required; unauthenticated mode removed \
             (set SOVRIGHT_RELAY_AUTH_KEY_HEX or SOVRIGHT_RELAY_AUTH_KEYS_HEX)"
            .into());
    }
    Ok(())
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

fn micros_from_duration(
    duration: Duration,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    Ok(duration.as_micros().try_into()?)
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
            "sovright-relay-relay-metrics-test-{}-{suffix}",
            std::process::id()
        ));
        let path = dir.join("metrics.prom");

        write_metrics_textfile(&path, "old_metric 1\n").unwrap();
        write_metrics_textfile(&path, "new_metric 2\n").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "new_metric 2\n");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn require_auth_keys_errors_when_empty() {
        let result = require_auth_keys(&[]);
        let err = result.expect_err("missing auth keys must be a startup error");
        let message = err.to_string();
        assert!(
            message.contains("unauthenticated mode removed"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn require_auth_keys_accepts_configured_key() {
        assert!(require_auth_keys(&[AuthKey::new("fleet", [0x42; 32])]).is_ok());
    }

    fn hex64(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    #[test]
    fn parse_named_auth_key_accepts_labeled_entry() {
        let hex = hex64(0xaa);
        let entry = format!("alice:{hex}");
        let key = parse_named_auth_key(&entry, 7).unwrap();
        assert_eq!(key.id, "alice");
        assert_eq!(key.key, [0xaa; 32]);
    }

    #[test]
    fn parse_named_auth_key_derives_id_for_bare_entry() {
        let hex = hex64(0xbb);
        let key = parse_named_auth_key(&hex, 3).unwrap();
        assert_eq!(key.id, "key3");
        assert_eq!(key.key, [0xbb; 32]);
    }

    #[test]
    fn parse_named_auth_key_rejects_bad_id() {
        let hex = hex64(0xcc);
        let entry = format!("bad id!:{hex}");
        let result = parse_named_auth_key(&entry, 0);
        assert!(
            result.is_err(),
            "id with spaces/punctuation must be rejected"
        );
    }

    #[test]
    fn parse_named_auth_key_rejects_id_over_32_chars() {
        let hex = hex64(0xdd);
        let long_id = "a".repeat(33);
        let entry = format!("{long_id}:{hex}");
        assert!(parse_named_auth_key(&entry, 0).is_err());
    }

    #[test]
    fn is_valid_key_id_rejects_reserved_unauthenticated_sentinel() {
        assert!(
            !is_valid_key_id("unauthenticated"),
            "the reserved unauthenticated-session sentinel must not be usable as a configured key id"
        );
        // Ordinary ids remain valid.
        assert!(is_valid_key_id("fleet"));
        assert!(is_valid_key_id("alice"));
    }

    #[test]
    fn parse_named_auth_key_rejects_reserved_unauthenticated_sentinel() {
        let hex = hex64(0xee);
        let entry = format!("unauthenticated:{hex}");
        assert!(
            parse_named_auth_key(&entry, 0).is_err(),
            "an auth key labeled with the reserved sentinel must be a startup error"
        );
    }

    #[test]
    fn require_unique_key_ids_detects_duplicates() {
        let keys = vec![
            AuthKey::new("fleet", [0x01; 32]),
            AuthKey::new("fleet", [0x02; 32]),
        ];
        let err = require_unique_key_ids(&keys).expect_err("duplicate ids must error");
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn require_unique_key_ids_accepts_distinct_ids() {
        let keys = vec![
            AuthKey::new("fleet", [0x01; 32]),
            AuthKey::new("alice", [0x02; 32]),
        ];
        assert!(require_unique_key_ids(&keys).is_ok());
    }

    /// Serializes tests that mutate process-wide env vars, since Rust runs
    /// `#[test]`s in parallel by default and env vars are process-global.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn auth_keys_from_env_combines_singular_and_labeled_list() {
        let _guard = ENV_LOCK.lock().unwrap();
        let fleet_hex = hex64(0x11);
        let alice_hex = hex64(0x22);
        let bare_hex = hex64(0x33);
        unsafe {
            env::set_var("SOVRIGHT_RELAY_AUTH_KEY_HEX", &fleet_hex);
            env::set_var(
                "SOVRIGHT_RELAY_AUTH_KEYS_HEX",
                format!("alice:{alice_hex},{bare_hex}"),
            );
        }

        let result = auth_keys_from_env();

        unsafe {
            env::remove_var("SOVRIGHT_RELAY_AUTH_KEY_HEX");
            env::remove_var("SOVRIGHT_RELAY_AUTH_KEYS_HEX");
        }

        let keys = result.unwrap();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].id, "fleet");
        assert_eq!(keys[0].key, [0x11; 32]);
        assert_eq!(keys[1].id, "alice");
        assert_eq!(keys[1].key, [0x22; 32]);
        // Bare entry is index 1 within the SOVRIGHT_RELAY_AUTH_KEYS_HEX list.
        assert_eq!(keys[2].id, "key1");
        assert_eq!(keys[2].key, [0x33; 32]);
    }

    #[test]
    fn auth_keys_from_env_errors_on_duplicate_id_across_both_vars() {
        let _guard = ENV_LOCK.lock().unwrap();
        let fleet_hex = hex64(0x44);
        let dup_hex = hex64(0x55);
        unsafe {
            env::set_var("SOVRIGHT_RELAY_AUTH_KEY_HEX", &fleet_hex);
            env::set_var("SOVRIGHT_RELAY_AUTH_KEYS_HEX", format!("fleet:{dup_hex}"));
        }

        let result = auth_keys_from_env();

        unsafe {
            env::remove_var("SOVRIGHT_RELAY_AUTH_KEY_HEX");
            env::remove_var("SOVRIGHT_RELAY_AUTH_KEYS_HEX");
        }

        let err = result.expect_err("duplicate id across the two env vars must be a startup error");
        assert!(err.to_string().contains("duplicate"));
    }
}
