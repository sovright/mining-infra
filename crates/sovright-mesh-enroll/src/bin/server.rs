//! PoC enrollment service (see docs/miner-onboarding.md §5).
//!
//! Endpoints (JSON over loopback HTTP — production terminates TLS):
//!   POST /v1/invite  {ops_token, pool, ttl_secs}      -> {invite_code}         (ops)
//!   POST /v1/enroll  {invite_code,miner_id,mesh_key_hex,node_endpoint} -> Enrollment
//!   POST /v1/revoke  {ops_token, miner_id}            -> {revoked}             (ops)
//!   GET  /healthz                                     -> {status, enrolled}
//!
//! On a successful enroll it rewrites the authorized-key store file that the
//! relays read into `RelayConfig.authorized_keys` — the concrete "key is
//! automatically added to the mesh" step.

use std::env;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use sovright_mesh_enroll::{EnrollRequest, InviteStore, KeyStore, enroll, http, new_invite_code};

/// Constant-time equality for the ops token. Both inputs are hashed to a
/// fixed-length SHA-256 digest first (so the comparison time reveals neither
/// the length nor the content of the secret), then compared with `subtle`'s
/// volatile-fold constant-time equality — the same primitives the relay
/// transport uses for its HMAC tag check.
fn ops_token_eq(a: &str, b: &str) -> bool {
    let da = Sha256::digest(a.as_bytes());
    let db = Sha256::digest(b.as_bytes());
    da.ct_eq(&db).into()
}

struct State {
    invites: InviteStore,
    keys: KeyStore,
    mesh_peers: Vec<SocketAddr>,
    ops_token: String,
    keystore_path: String,
}

/// Wall-clock seconds since the Unix epoch, or `None` if the system clock is
/// before the epoch (an error the kernel should never produce, but which we
/// must not paper over). Callers treat `None` as a hard failure rather than
/// substituting 0: a 0 timestamp would stamp bogus `expires_at` values at issue
/// time *and* make every existing invite look un-expired at check time
/// (fail-open). Returning `None` keeps the failure explicit at both sites.
fn now_secs() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .ok()
}

/// True only if `bind` can be *proven* to be a loopback endpoint. Resolves the
/// bind via DNS (for the socket layer, a hostname bind resolves the same way)
/// and requires the resolution to be non-empty and every resolved address to be
/// loopback. The literal host `localhost` is accepted directly since some
/// resolver configs surprise us. Any resolution failure or a mix of addresses is
/// treated as "not proven" -> caller requires TLS.
fn bind_is_proven_loopback(bind: &str) -> bool {
    // Treat a literal "localhost" host as loopback regardless of resolver quirks.
    if let Some((host, _port)) = bind.rsplit_once(':')
        && host.eq_ignore_ascii_case("localhost")
    {
        return true;
    }
    // Resolve once and collect (the iterator must not be consumed twice).
    match bind.to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<SocketAddr> = addrs.collect();
            !addrs.is_empty() && addrs.iter().all(|a| a.ip().is_loopback())
        }
        Err(_) => false,
    }
}

/// Max concurrent connection-handler threads. Each handler runs Equihash-free,
/// short-lived work but spawns an OS thread; without a bound a flood of
/// connections would spawn threads until the process exhausts memory/FDs. Excess
/// connections are dropped (their socket closes) rather than queued.
const MAX_CONNECTIONS: usize = 128;

/// RAII guard that decrements the live-connection counter on every exit path of
/// a handler thread (normal return, early return, or panic unwinding).
struct ConnGuard(Arc<AtomicUsize>);
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn main() -> std::io::Result<()> {
    let bind = env::var("SOVRIGHT_ENROLL_BIND").unwrap_or_else(|_| "127.0.0.1:8088".into());
    let ops_token =
        env::var("SOVRIGHT_ENROLL_OPS_TOKEN").unwrap_or_else(|_| "dev-ops-token".into());
    let keystore_path =
        env::var("SOVRIGHT_ENROLL_KEYSTORE").unwrap_or_else(|_| "authorized_keys.json".into());
    let mesh_peers: Vec<SocketAddr> = env::var("SOVRIGHT_MESH_PEERS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    // Refuse to expose the plaintext endpoint off loopback. This PoC speaks
    // plain HTTP (no TLS in this crate); a non-loopback bind without TLS
    // configured would broadcast invite codes and mesh key material in the
    // clear. Treat SOVRIGHT_ENROLL_TLS_CERT being set as "TLS configured".
    let tls_configured = env::var_os("SOVRIGHT_ENROLL_TLS_CERT").is_some();
    // Fail CLOSED: a plaintext bind is only permitted if it can be PROVEN
    // loopback. A parse-based check let a non-IP hostname (e.g.
    // "host.example.com:8088") slip through and bind in the clear, because it
    // failed to parse as a SocketAddr and the guard never fired. Instead resolve
    // the bind and require the resolution to be non-empty and *every* resolved
    // address to be loopback; the literal host "localhost" is also treated as
    // loopback (some resolvers omit it). Anything we cannot prove is loopback is
    // treated as non-loopback and requires TLS.
    if !tls_configured && !bind_is_proven_loopback(&bind) {
        eprintln!(
            "[enroll] refusing to bind {bind}: address could not be proven loopback \
             and no TLS is configured — a non-loopback bind would expose invite codes \
             and mesh keys in cleartext. Bind to loopback (127.0.0.1:x, [::1]:x, \
             localhost:x), or set SOVRIGHT_ENROLL_TLS_CERT once TLS termination is \
             configured."
        );
        std::process::exit(1);
    }

    let state = Arc::new(Mutex::new(State {
        invites: InviteStore::new(),
        keys: KeyStore::new(),
        mesh_peers,
        ops_token,
        keystore_path,
    }));

    let listener = TcpListener::bind(&bind)?;
    eprintln!("[enroll] listening on {bind} (PoC: plain HTTP, loopback only — TLS in prod)");
    eprintln!(
        "[enroll] ops token via SOVRIGHT_ENROLL_OPS_TOKEN; keystore -> {}",
        state.lock().unwrap().keystore_path
    );

    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[enroll] accept error: {e}");
                continue;
            }
        };
        // Enforce a global connection cap before spawning a worker. Reserve a
        // slot with a single atomic increment; if we blew past the cap, undo the
        // reservation, refuse the connection, and drop the stream (which closes
        // it) without spawning a thread.
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            let _ = std::io::Write::write_all(
                &mut stream,
                &reply(503, "Service Unavailable", json!({"error":"too many connections"})),
            );
            eprintln!("[enroll] connection cap ({MAX_CONNECTIONS}) reached; refusing connection");
            continue;
        }
        let guard = ConnGuard(Arc::clone(&active));
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            // Decrement the live-connection count on any exit path.
            let _guard = guard;
            let mut stream = stream;
            // Bound how long a slow/stalled client can hold a worker thread.
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            match http::read_request(&mut stream) {
                Ok((head, body)) => {
                    let resp = handle(&state, &head.method, &head.path, &body);
                    let _ = std::io::Write::write_all(&mut stream, &resp);
                }
                Err(e) => eprintln!("[enroll] read error: {e}"),
            }
        });
    }
    Ok(())
}

#[derive(Deserialize)]
struct IssueReq {
    ops_token: String,
    pool: String,
    #[serde(default = "default_ttl")]
    ttl_secs: u64,
}
fn default_ttl() -> u64 {
    7 * 24 * 3600
}

#[derive(Deserialize)]
struct RevokeReq {
    ops_token: String,
    miner_id: String,
}

fn handle(state: &Arc<Mutex<State>>, method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    match (method, path) {
        ("GET", "/healthz") => {
            let st = state.lock().unwrap();
            reply(
                200,
                "OK",
                json!({"status":"ok","enrolled": st.keys.active_count()}),
            )
        }
        ("POST", "/v1/invite") => {
            let req: IssueReq = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => return reply(400, "Bad Request", json!({"error": e.to_string()})),
            };
            let mut st = state.lock().unwrap();
            if !ops_token_eq(&req.ops_token, &st.ops_token) {
                return reply(401, "Unauthorized", json!({"error":"bad ops token"}));
            }
            // Validate the pool label at ISSUE time so the stored invite (which is
            // later logged and returned to the enrolling node) can never carry
            // control chars or unbounded input. Mirrors the miner_id check in enroll().
            if !sovright_mesh_enroll::valid_ident(&req.pool) {
                return reply(
                    400,
                    "Bad Request",
                    json!({"error":"pool must be 1-64 chars of [A-Za-z0-9_-]"}),
                );
            }
            let now = match now_secs() {
                Some(n) => n,
                None => return reply(500, "Internal Server Error", json!({"error":"clock error"})),
            };
            let code = st
                .invites
                .issue(new_invite_code(), &req.pool, now, req.ttl_secs);
            reply(200, "OK", json!({"invite_code": code, "pool": req.pool}))
        }
        ("POST", "/v1/enroll") => {
            let req: EnrollRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => return reply(400, "Bad Request", json!({"error": e.to_string()})),
            };
            let now = match now_secs() {
                Some(n) => n,
                None => return reply(500, "Internal Server Error", json!({"error":"clock error"})),
            };
            let mut guard = state.lock().unwrap();
            let st = &mut *guard;
            let peers = st.mesh_peers.clone();
            match enroll(&mut st.invites, &mut st.keys, &peers, &req, now) {
                Ok(enr) => {
                    persist_keystore(st);
                    eprintln!(
                        "[enroll] miner '{}' (pool '{}') enrolled; mesh now has {} keys",
                        enr.miner_id,
                        enr.pool,
                        st.keys.active_count()
                    );
                    reply(200, "OK", serde_json::to_value(&enr).unwrap())
                }
                Err(e) => reply(e.http_status(), "Error", json!({"error": e.to_string()})),
            }
        }
        ("POST", "/v1/revoke") => {
            let req: RevokeReq = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => return reply(400, "Bad Request", json!({"error": e.to_string()})),
            };
            let mut st = state.lock().unwrap();
            if !ops_token_eq(&req.ops_token, &st.ops_token) {
                return reply(401, "Unauthorized", json!({"error":"bad ops token"}));
            }
            let revoked = st.keys.revoke(&req.miner_id);
            if revoked {
                persist_keystore(&st);
            }
            reply(200, "OK", json!({"revoked": revoked}))
        }
        _ => reply(404, "Not Found", json!({"error":"no such route"})),
    }
}

fn reply(status: u16, reason: &str, body: serde_json::Value) -> Vec<u8> {
    http::json_response(status, reason, &body.to_string())
}

/// Render the active mesh keys + peers to the file the relays reload (§6).
///
/// The file holds mesh HMAC secrets, so: (a) write to a temp file in the same
/// directory and atomically `rename` it onto the target — a crash mid-write
/// never leaves the relays a truncated/partial keystore; (b) on Unix create the
/// temp file 0600 before the rename so the secrets are never briefly world-
/// readable.
fn persist_keystore(st: &State) {
    let keys: Vec<String> = st.keys.authorized_keys().iter().map(hex::encode).collect();
    let peers: Vec<String> = st.keys.peers().iter().map(|p| p.to_string()).collect();
    let doc = json!({"authorized_keys": keys, "peers": peers});
    if let Err(e) = write_atomic(&st.keystore_path, doc.to_string().as_bytes()) {
        eprintln!(
            "[enroll] WARN could not write keystore {}: {e}",
            st.keystore_path
        );
    }
}

/// Atomic, 0600 (Unix) file write: write a sibling temp file then rename.
fn write_atomic(path: &str, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let target = std::path::Path::new(path);
    let dir = target.parent().filter(|p| !p.as_os_str().is_empty());
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("keystore");
    let tmp_name = format!(".{file_name}.tmp.{}", std::process::id());
    let tmp_path = match dir {
        Some(d) => d.join(&tmp_name),
        None => std::path::PathBuf::from(&tmp_name),
    };

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp_path)?;
    f.write_all(contents)?;
    f.flush()?;
    drop(f);

    if let Err(e) = std::fs::rename(&tmp_path, target) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> Arc<Mutex<State>> {
        Arc::new(Mutex::new(State {
            invites: InviteStore::new(),
            keys: KeyStore::new(),
            mesh_peers: vec![],
            ops_token: "tok".into(),
            keystore_path: "/dev/null/nope".into(),
        }))
    }

    /// Parse the numeric status out of a `handle` response (first line: "HTTP/1.1 <code> ...").
    fn status_of(resp: &[u8]) -> u16 {
        let text = String::from_utf8_lossy(resp);
        text.split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap()
    }

    #[test]
    fn invite_rejects_bad_pool() {
        let st = test_state();
        // A pool label with a newline must be rejected 400 at issue time and
        // must not issue an invite.
        for bad in ["evil\npool", &"p".repeat(65), "", "has space", "dots.bad"] {
            let body = json!({"ops_token":"tok","pool": bad}).to_string();
            let resp = handle(&st, "POST", "/v1/invite", body.as_bytes());
            assert_eq!(status_of(&resp), 400, "bad pool {bad:?} -> 400");
        }
    }

    #[test]
    fn invite_accepts_good_pool() {
        let st = test_state();
        let body = json!({"ops_token":"tok","pool":"pool-a"}).to_string();
        let resp = handle(&st, "POST", "/v1/invite", body.as_bytes());
        assert_eq!(status_of(&resp), 200);
    }

    #[test]
    fn invite_bad_ops_token_still_401() {
        let st = test_state();
        let body = json!({"ops_token":"wrong","pool":"pool-a"}).to_string();
        let resp = handle(&st, "POST", "/v1/invite", body.as_bytes());
        assert_eq!(status_of(&resp), 401);
    }

    #[test]
    fn loopback_prover_accepts_genuine_loopback() {
        assert!(bind_is_proven_loopback("127.0.0.1:8088"));
        assert!(bind_is_proven_loopback("[::1]:8088"));
        assert!(bind_is_proven_loopback("localhost:8088"));
        assert!(bind_is_proven_loopback("LOCALHOST:8088"));
    }

    #[test]
    fn loopback_prover_rejects_non_loopback_and_unresolvable() {
        // Public IP is not loopback.
        assert!(!bind_is_proven_loopback("8.8.8.8:8088"));
        assert!(!bind_is_proven_loopback("0.0.0.0:8088"));
        // A non-IP hostname that isn't "localhost" cannot be proven loopback:
        // either it fails to resolve or resolves to non-loopback -> false.
        // (Uses .invalid, reserved by RFC 6761 to never resolve.)
        assert!(!bind_is_proven_loopback("nope.invalid:8088"));
    }

    #[test]
    fn now_secs_is_some_and_sane() {
        // Sanity: on a healthy clock now_secs yields a plausible recent epoch.
        let n = now_secs().expect("clock should be after epoch");
        assert!(n > 1_600_000_000, "expected a post-2020 timestamp, got {n}");
    }
}
