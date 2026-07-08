use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{env, fs};

use sovright_relay::{ArrivalSink, AuthKey, RelayConfig, RelayNode, render_prometheus_text};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sovright_relay=info".parse()?),
        )
        .init();

    let (config, auth_keys_resolution) = config_from_env()?;
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

    // Hot revocation (PR-B): only spawned when SOVRIGHT_RELAY_AUTH_KEYS_FILE
    // is set. When unset, `auth_keys_resolution.keys_file` is None and no
    // task is spawned -- behavior is then identical to PR #75 (env-only,
    // static authorized_keys for the lifetime of the process).
    if let Some(keys_file) = auth_keys_resolution.keys_file.clone() {
        info!(
            path = %keys_file.display(),
            reload_secs = auth_keys_resolution.reload_secs,
            "Hot auth-key revocation enabled; watching keys file"
        );
        spawn_auth_keys_reload_task(
            Arc::clone(&node),
            auth_keys_resolution.env_keys,
            auth_keys_resolution.initial_file_keys,
            keys_file,
            auth_keys_resolution.reload_secs,
        );
    }

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

/// Result of resolving the relay's authorized-key configuration at startup.
struct AuthKeysResolution {
    /// Initial active set = `env_keys` union the file's keys at startup (or
    /// `env_keys` alone if the file env var is unset, or the file could not
    /// be read/parsed at startup).
    active: Vec<AuthKey>,
    /// The permanent, env-configured base keys. Always present in every
    /// future active set the reload task computes; never hot-removable.
    env_keys: Vec<AuthKey>,
    /// File-sourced keys successfully loaded at startup (empty if the file
    /// env var is unset or the file could not be read/parsed at startup).
    /// Seeds the reload task's "last known good" file-key set so the first
    /// tick logs an accurate added/removed diff.
    initial_file_keys: Vec<AuthKey>,
    /// Path to the hot-swappable keys file, if `SOVRIGHT_RELAY_AUTH_KEYS_FILE`
    /// is set. `None` means the hot-revocation feature is entirely off.
    keys_file: Option<PathBuf>,
    /// Reload interval in seconds (`SOVRIGHT_RELAY_AUTH_KEYS_RELOAD_SECS`,
    /// default 15). Only meaningful when `keys_file` is `Some`.
    reload_secs: u64,
}

/// Resolve the relay's authorized keys: the permanent env-configured base
/// plus, if `SOVRIGHT_RELAY_AUTH_KEYS_FILE` is set, the file's keys.
///
/// A missing or unparsable keys file at STARTUP is not a hard error -- the
/// relay starts with the env-only base and the reload task will pick up the
/// file whenever it becomes valid. This mirrors the reload task's own
/// fail-safe behavior (see `spawn_auth_keys_reload_task`): a bad file never
/// removes the env/fleet keys, it just means the file's keys aren't active
/// yet.
fn resolve_auth_keys() -> Result<AuthKeysResolution, Box<dyn std::error::Error + Send + Sync>> {
    let env_keys = auth_keys_from_env()?;
    require_auth_keys(&env_keys)?;

    let keys_file = env::var_os("SOVRIGHT_RELAY_AUTH_KEYS_FILE").map(PathBuf::from);
    let reload_secs = env_u64("SOVRIGHT_RELAY_AUTH_KEYS_RELOAD_SECS", 15)?;

    let (active, initial_file_keys) = match &keys_file {
        None => (env_keys.clone(), Vec::new()),
        Some(path) => match read_auth_keys_file(path) {
            Ok(file_keys) => match build_active_key_set(&env_keys, &file_keys) {
                Ok(active) => (active, file_keys),
                Err(error) => {
                    warn!(
                        %error,
                        path = %path.display(),
                        "Auth keys file failed union validation at startup; starting with env keys only"
                    );
                    (env_keys.clone(), Vec::new())
                }
            },
            Err(error) => {
                warn!(
                    %error,
                    path = %path.display(),
                    "Failed to read auth keys file at startup; starting with env keys only"
                );
                (env_keys.clone(), Vec::new())
            }
        },
    };

    Ok(AuthKeysResolution {
        active,
        env_keys,
        initial_file_keys,
        keys_file,
        reload_secs,
    })
}

/// Parse an auth-keys file's contents: one `id:hex64` entry per line.
/// Blank lines and lines starting with `#` are ignored. Reuses
/// `parse_named_auth_key` per line (a bare `hex64` line, with no `id:`
/// prefix, is accepted the same way it is for `SOVRIGHT_RELAY_AUTH_KEYS_HEX`,
/// deriving an id from the line's 0-based position).
fn parse_auth_keys_file_contents(
    contents: &str,
) -> Result<Vec<AuthKey>, Box<dyn std::error::Error + Send + Sync>> {
    let mut keys = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        keys.push(parse_named_auth_key(line, index)?);
    }
    Ok(keys)
}

fn read_auth_keys_file(
    path: &Path,
) -> Result<Vec<AuthKey>, Box<dyn std::error::Error + Send + Sync>> {
    let contents = fs::read_to_string(path)?;
    parse_auth_keys_file_contents(&contents)
}

/// Collect auth keys into an order-insensitive set of `(id, key-bytes)` pairs
/// for change detection. Two key lists that contain the same entries in a
/// different order compare equal, so a mere reordering of the file's lines is
/// not treated as a semantic change.
fn auth_key_set(keys: &[AuthKey]) -> HashSet<(String, [u8; 32])> {
    keys.iter().map(|k| (k.id.clone(), k.key)).collect()
}

/// Build the active key set = `env_keys` union `file_keys`, validating that
/// every id is unique across the union (reuses `require_unique_key_ids`).
fn build_active_key_set(
    env_keys: &[AuthKey],
    file_keys: &[AuthKey],
) -> Result<Vec<AuthKey>, Box<dyn std::error::Error + Send + Sync>> {
    let mut union = env_keys.to_vec();
    union.extend(file_keys.iter().cloned());
    require_unique_key_ids(&union)?;
    Ok(union)
}

/// Spawn the background task that watches `path` for changes and hot-swaps
/// the relay's active authorized-key set (PR-B: hot revocation).
///
/// On each tick: re-read and re-parse the file, rebuild
/// `active = env_keys UNION file_keys`, and -- only if the file's keys
/// actually changed since the last successful reload -- apply the new
/// active set to `node` (which also evicts sessions bound to removed keys)
/// and log the added/removed key ids.
///
/// Fail-safe: if the file is unreadable, or parsing/validation fails (bad
/// id, malformed line, duplicate id across the union), the previous good
/// active set is left untouched and a warning is logged. The env/fleet keys
/// passed in `env_keys` are therefore always present in every active set
/// this task ever applies -- a bad file can never remove them.
fn spawn_auth_keys_reload_task(
    node: Arc<RelayNode>,
    env_keys: Vec<AuthKey>,
    initial_file_keys: Vec<AuthKey>,
    path: PathBuf,
    reload_secs: u64,
) {
    let reload_handle = tokio::spawn(async move {
        let mut last_good_file_keys = initial_file_keys;
        let mut interval = tokio::time::interval(Duration::from_secs(reload_secs.max(1)));
        // The first tick fires immediately; skip it since the initial active
        // set was already applied at construction time via RelayNode::new.
        interval.tick().await;
        loop {
            interval.tick().await;
            // The fs read is blocking; run it off the async worker so a slow
            // or stalled disk read can't hold up this runtime thread. Only the
            // read+parse is moved -- everything else (union, diff, apply) stays
            // on the async path. A JoinError (blocking task panicked/cancelled)
            // is treated exactly like an IO/parse error: keep the previous good
            // set. This preserves the fail-safe semantics.
            let read_path = path.clone();
            let read_result =
                tokio::task::spawn_blocking(move || read_auth_keys_file(&read_path)).await;
            let file_keys = match read_result {
                Ok(Ok(keys)) => keys,
                Ok(Err(error)) => {
                    warn!(
                        %error,
                        path = %path.display(),
                        "Failed to read auth keys file on reload; keeping previous active key set"
                    );
                    continue;
                }
                Err(join_error) => {
                    warn!(
                        %join_error,
                        path = %path.display(),
                        "Auth keys file read task failed to join on reload; keeping previous active key set"
                    );
                    continue;
                }
            };

            let active = match build_active_key_set(&env_keys, &file_keys) {
                Ok(active) => active,
                Err(error) => {
                    warn!(
                        %error,
                        path = %path.display(),
                        "Auth keys file failed union validation on reload; keeping previous active key set"
                    );
                    continue;
                }
            };

            // Order-insensitive change detection: reordering the same
            // (id, key-bytes) entries in the file is not a semantic change,
            // so compare as sets rather than by Vec position.
            if auth_key_set(&file_keys) == auth_key_set(&last_good_file_keys) {
                continue;
            }

            let old_ids: HashSet<&str> =
                last_good_file_keys.iter().map(|k| k.id.as_str()).collect();
            let new_ids: HashSet<&str> = file_keys.iter().map(|k| k.id.as_str()).collect();
            let added: Vec<&str> = new_ids.difference(&old_ids).copied().collect();
            let removed: Vec<&str> = old_ids.difference(&new_ids).copied().collect();

            info!(
                ?added,
                ?removed,
                path = %path.display(),
                "Auth keys file changed; applying new active key set"
            );
            node.apply_active_keys(active).await;
            last_good_file_keys = file_keys;
            // Liveness signal: stamp the wall-clock time of this successful
            // apply so operators can alert when the reload loop stops advancing
            // it (which would mean hot revocation is no longer being applied).
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            node.metrics().set_last_auth_keys_reload_unix(now_unix);
        }
    });

    // Supervisor: the reload loop above is meant to run for the entire process
    // lifetime. If it ever returns (loop body somehow breaks) or panics, hot
    // revocation is silently disabled -- fire-and-forget would swallow that.
    // Await the JoinHandle and log at error! so it is alertable. We do NOT
    // restart it: a terminating long-lived loop is a bug, and the loop's own
    // fail-safe (keep the previous good key set on any per-tick error) means a
    // stuck/removed keys file never reaches this point.
    tokio::spawn(async move {
        match reload_handle.await {
            Ok(()) => error!(
                "Auth keys reload task exited unexpectedly; hot revocation DISABLED for the process lifetime"
            ),
            Err(join_error) => error!(
                %join_error,
                "Auth keys reload task panicked; hot revocation DISABLED for the process lifetime"
            ),
        }
    });
}

fn config_from_env()
-> Result<(RelayConfig, AuthKeysResolution), Box<dyn std::error::Error + Send + Sync>> {
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

    let auth_keys_resolution = resolve_auth_keys()?;
    config = config
        .with_authorized_keys(auth_keys_resolution.active.clone())
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

    Ok((config, auth_keys_resolution))
}

/// Identity label allowed for a configured auth key: `[A-Za-z0-9_-]{1,32}`.
fn is_valid_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
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

    fn unique_temp_path(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!(
            "sovright-relay-auth-keys-file-{label}-{}-{suffix}",
            std::process::id()
        ))
    }

    // --- File parsing -------------------------------------------------

    #[test]
    fn parse_auth_keys_file_contents_skips_blank_lines_and_comments() {
        let alice_hex = hex64(0xaa);
        let bob_hex = hex64(0xbb);
        let contents = format!(
            "# fleet invitee keys\n\nalice:{alice_hex}\n\n# a comment line\nbob:{bob_hex}\n"
        );

        let keys = parse_auth_keys_file_contents(&contents).unwrap();

        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].id, "alice");
        assert_eq!(keys[0].key, [0xaa; 32]);
        assert_eq!(keys[1].id, "bob");
        assert_eq!(keys[1].key, [0xbb; 32]);
    }

    #[test]
    fn parse_auth_keys_file_contents_rejects_bad_id() {
        let hex = hex64(0xcc);
        let contents = format!("bad id!:{hex}\n");
        assert!(parse_auth_keys_file_contents(&contents).is_err());
    }

    #[test]
    fn build_active_key_set_rejects_duplicate_id_across_env_and_file() {
        let env_keys = vec![AuthKey::new("fleet", [0x01; 32])];
        let file_keys = vec![AuthKey::new("fleet", [0x02; 32])];
        let err = build_active_key_set(&env_keys, &file_keys)
            .expect_err("duplicate id across env and file must be rejected");
        assert!(err.to_string().contains("duplicate"));
    }

    // --- Active-set rebuild --------------------------------------------

    #[test]
    fn build_active_key_set_is_env_union_file() {
        let env_keys = vec![AuthKey::new("fleet", [0x01; 32])];
        let file_keys = vec![
            AuthKey::new("alice", [0x02; 32]),
            AuthKey::new("bob", [0x03; 32]),
        ];

        let active = build_active_key_set(&env_keys, &file_keys).unwrap();

        assert_eq!(active.len(), 3);
        assert!(active.contains(&AuthKey::new("fleet", [0x01; 32])));
        assert!(active.contains(&AuthKey::new("alice", [0x02; 32])));
        assert!(active.contains(&AuthKey::new("bob", [0x03; 32])));
    }

    #[test]
    fn build_active_key_set_reflects_removed_file_line() {
        let env_keys = vec![AuthKey::new("fleet", [0x01; 32])];
        let file_keys_before = vec![
            AuthKey::new("alice", [0x02; 32]),
            AuthKey::new("bob", [0x03; 32]),
        ];
        let file_keys_after = vec![AuthKey::new("bob", [0x03; 32])];

        let before = build_active_key_set(&env_keys, &file_keys_before).unwrap();
        let after = build_active_key_set(&env_keys, &file_keys_after).unwrap();

        assert!(before.iter().any(|k| k.id == "alice"));
        assert!(
            !after.iter().any(|k| k.id == "alice"),
            "removing alice's line from the file must remove her from the rebuilt active set"
        );
        assert!(after.iter().any(|k| k.id == "bob"));
    }

    #[test]
    fn build_active_key_set_always_includes_env_keys_regardless_of_file_content() {
        let env_keys = vec![AuthKey::new("fleet", [0x01; 32])];

        let with_empty_file = build_active_key_set(&env_keys, &[]).unwrap();
        assert!(with_empty_file.iter().any(|k| k.id == "fleet"));

        let with_other_file_keys =
            build_active_key_set(&env_keys, &[AuthKey::new("alice", [0x02; 32])]).unwrap();
        assert!(with_other_file_keys.iter().any(|k| k.id == "fleet"));
    }

    // --- Reload fail-safe -----------------------------------------------

    #[test]
    fn reload_fail_safe_unreadable_file_leaves_previous_set_unchanged() {
        // Simulates one reload tick's decision logic against a path that was
        // never created: the caller (spawn_auth_keys_reload_task) must treat
        // a read error as "keep the previous good set", never as empty.
        let env_keys = vec![AuthKey::new("fleet", [0x01; 32])];
        let last_good_file_keys = vec![AuthKey::new("alice", [0x02; 32])];
        let missing_path = unique_temp_path("missing");

        let read_result = read_auth_keys_file(&missing_path);
        assert!(
            read_result.is_err(),
            "reading a nonexistent file must error"
        );

        // The active set the reload task would still be serving is the one
        // built from the last known good file keys -- non-empty, includes
        // both env and previously-loaded file keys.
        let still_active = build_active_key_set(&env_keys, &last_good_file_keys).unwrap();
        assert!(!still_active.is_empty());
        assert!(still_active.iter().any(|k| k.id == "fleet"));
        assert!(still_active.iter().any(|k| k.id == "alice"));
    }

    #[test]
    fn reload_fail_safe_garbled_file_leaves_previous_set_unchanged() {
        let path = unique_temp_path("garbled");
        fs::write(&path, "not-a-valid-line-without-colon-or-hex\n").unwrap();

        let file_keys = read_auth_keys_file(&path);
        fs::remove_file(&path).ok();

        assert!(
            file_keys.is_err(),
            "a garbled line must fail parsing so the reload task keeps the previous set"
        );
    }

    #[test]
    fn reload_fail_safe_duplicate_id_leaves_previous_set_unchanged() {
        let env_keys = vec![AuthKey::new("fleet", [0x01; 32])];
        let path = unique_temp_path("dup-id");
        fs::write(&path, format!("fleet:{}\n", hex64(0x02))).unwrap();

        let file_keys = read_auth_keys_file(&path).unwrap();
        fs::remove_file(&path).ok();
        let result = build_active_key_set(&env_keys, &file_keys);

        assert!(
            result.is_err(),
            "a file key colliding with an env key id must fail union validation"
        );
    }

    // --- Back-compat ------------------------------------------------------

    #[test]
    fn resolve_auth_keys_is_env_only_when_file_env_var_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::remove_var("SOVRIGHT_RELAY_AUTH_KEYS_FILE");
            env::set_var("SOVRIGHT_RELAY_AUTH_KEY_HEX", hex64(0x66));
        }

        let resolution = resolve_auth_keys().unwrap();

        unsafe {
            env::remove_var("SOVRIGHT_RELAY_AUTH_KEY_HEX");
        }

        assert!(
            resolution.keys_file.is_none(),
            "hot-revocation must be entirely off when the file env var is unset"
        );
        assert_eq!(resolution.active, resolution.env_keys);
        assert_eq!(resolution.active.len(), 1);
        assert_eq!(resolution.active[0].id, "fleet");
    }

    // --- Eviction (integration): file-driven rebuild feeding apply_active_keys --
    //
    // The critical session-eviction assertion itself (a session bound to a
    // revoked key_id is dropped while a session bound to an env/fleet
    // key_id survives the same reload cycle) lives in
    // crates/sovright-relay/src/relay/node.rs
    // (`apply_active_keys_evicts_sessions_bound_to_removed_keys`), since
    // `RelayNode::sessions` is only visible to same-crate tests. This test
    // covers the piece that lives in this binary: that a file-driven active-
    // set rebuild (as `spawn_auth_keys_reload_task` performs on each tick)
    // correctly feeds `RelayNode::apply_active_keys`, revoking the removed
    // file key while the env/fleet key remains authorized.
    #[tokio::test]
    async fn file_driven_rebuild_revokes_removed_key_via_apply_active_keys() {
        use sovright_relay::{RelayConfig, RelayNode};

        let fleet_key = [0x01; 32];
        let alice_key = [0x02; 32];
        let env_keys = vec![AuthKey::new("fleet", fleet_key)];
        let file_keys_initial = vec![AuthKey::new("alice", alice_key)];
        let active_initial = build_active_key_set(&env_keys, &file_keys_initial).unwrap();

        let config =
            RelayConfig::new("127.0.0.1:0".parse().unwrap()).with_authorized_keys(active_initial);
        let node = RelayNode::new(config).unwrap();
        assert!(node.is_authorized(&alice_key));

        // Alice's line is removed from the file; rebuild the active set the
        // same way spawn_auth_keys_reload_task does on a tick.
        let active_after = build_active_key_set(&env_keys, &[]).unwrap();
        assert!(active_after.iter().any(|k| k.id == "fleet"));
        assert!(!active_after.iter().any(|k| k.id == "alice"));

        node.apply_active_keys(active_after).await;

        assert!(
            node.is_authorized(&fleet_key),
            "env/fleet key must remain authorized after a file-only revocation"
        );
        assert!(
            !node.is_authorized(&alice_key),
            "file-sourced key removed from the file must no longer authorize"
        );
    }
}
