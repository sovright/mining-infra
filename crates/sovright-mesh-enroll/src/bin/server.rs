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
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::json;
use sovright_mesh_enroll::{EnrollRequest, InviteStore, KeyStore, enroll, http, new_invite_code};

struct State {
    invites: InviteStore,
    keys: KeyStore,
    mesh_peers: Vec<SocketAddr>,
    ops_token: String,
    keystore_path: String,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[enroll] accept error: {e}");
                continue;
            }
        };
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let mut stream = stream;
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
            if req.ops_token != st.ops_token {
                return reply(401, "Unauthorized", json!({"error":"bad ops token"}));
            }
            let code = st
                .invites
                .issue(new_invite_code(), &req.pool, now_secs(), req.ttl_secs);
            reply(200, "OK", json!({"invite_code": code, "pool": req.pool}))
        }
        ("POST", "/v1/enroll") => {
            let req: EnrollRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => return reply(400, "Bad Request", json!({"error": e.to_string()})),
            };
            let mut guard = state.lock().unwrap();
            let st = &mut *guard;
            let peers = st.mesh_peers.clone();
            match enroll(&mut st.invites, &mut st.keys, &peers, &req, now_secs()) {
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
            if req.ops_token != st.ops_token {
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
fn persist_keystore(st: &State) {
    let keys: Vec<String> = st.keys.authorized_keys().iter().map(hex::encode).collect();
    let peers: Vec<String> = st.keys.peers().iter().map(|p| p.to_string()).collect();
    let doc = json!({"authorized_keys": keys, "peers": peers});
    if let Err(e) = std::fs::write(&st.keystore_path, doc.to_string()) {
        eprintln!(
            "[enroll] WARN could not write keystore {}: {e}",
            st.keystore_path
        );
    }
}
