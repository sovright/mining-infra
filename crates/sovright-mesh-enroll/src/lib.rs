//! Miner relay onboarding — enrollment PoC.
//!
//! Implements the enrollment flow from `docs/miner-onboarding.md` §4–6: a miner
//! deploys their own relay node, it generates a fresh mesh key locally, and
//! registers that key with this service over HTTPS using a single-use invite
//! code. On a valid invite the key is added to the **authorized-key store** that
//! the relays read into `RelayConfig.authorized_keys` — so the miner's node is
//! admitted to the mesh as an authenticated peer with no further human step.
//!
//! This crate is the pure logic (invite lifecycle, key gen/validation, the key
//! store, and the enroll orchestration) plus a thin loopback HTTP wire helper for
//! the PoC binaries. It is deliberately dep-light. In production:
//!   - the enroll hop is TLS (server-authenticated); this PoC is plain HTTP on
//!     loopback and says so;
//!   - the stores are durable + behind a transaction; here they are in-memory
//!     maps guarded by the caller's lock;
//!   - `now` is injected everywhere so the invite lifecycle is deterministically
//!     testable.

use std::collections::HashMap;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

pub mod http;

/// Reasons enrollment can fail. The HTTP layer maps these to status codes via
/// [`EnrollError::http_status`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnrollError {
    #[error("unknown invite code")]
    UnknownInvite,
    #[error("invite code has expired")]
    InviteExpired,
    #[error("invite code was already used")]
    InviteConsumed,
    #[error("invite code was revoked")]
    InviteRevoked,
    #[error("mesh key must be exactly 32 bytes (64 hex chars)")]
    BadKeyLength,
    #[error("mesh key is not valid hex")]
    BadKeyHex,
    #[error("mesh key must not be all-zero")]
    ZeroKey,
    #[error("node endpoint is not a valid ip:port")]
    BadEndpoint,
    #[error("miner id must be 1-64 chars of [A-Za-z0-9_-]")]
    BadMinerId,
    #[error("miner id is already enrolled")]
    DuplicateMiner,
}

impl EnrollError {
    /// HTTP status the enroll endpoint returns for this error (see §5).
    pub fn http_status(&self) -> u16 {
        match self {
            // Auth-ish failures: the invite is not a currently-valid credential.
            EnrollError::UnknownInvite
            | EnrollError::InviteExpired
            | EnrollError::InviteRevoked => 401,
            // Conflict: the credential/identity was already spent/taken.
            EnrollError::InviteConsumed | EnrollError::DuplicateMiner => 409,
            // Client sent something malformed.
            EnrollError::BadKeyLength
            | EnrollError::BadKeyHex
            | EnrollError::ZeroKey
            | EnrollError::BadEndpoint
            | EnrollError::BadMinerId => 400,
        }
    }
}

// ---------------------------------------------------------------------------
// Mesh key
// ---------------------------------------------------------------------------

/// A 32-byte symmetric mesh key — the same shape the relay transport HMACs with
/// (`transport/session.rs`). Miner-generated; never escrowed by the service.
#[derive(Clone, PartialEq, Eq)]
pub struct MeshKey([u8; 32]);

impl MeshKey {
    /// Generate a fresh key from the OS CSPRNG. Retries the (astronomically
    /// unlikely) all-zero draw so an enrolled key is never the rejected sentinel.
    pub fn generate() -> Self {
        loop {
            let mut k = [0u8; 32];
            getrandom::getrandom(&mut k).expect("OS CSPRNG unavailable");
            if k != [0u8; 32] {
                return MeshKey(k);
            }
        }
    }

    /// Parse a 64-char hex string into a key, rejecting wrong length, non-hex,
    /// and the all-zero key (which the mesh treats as "no key" — `node.rs`).
    pub fn from_hex(s: &str) -> Result<Self, EnrollError> {
        let s = s.trim();
        if s.len() != 64 {
            return Err(EnrollError::BadKeyLength);
        }
        let bytes = hex::decode(s).map_err(|_| EnrollError::BadKeyHex)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| EnrollError::BadKeyLength)?;
        if arr == [0u8; 32] {
            return Err(EnrollError::ZeroKey);
        }
        Ok(MeshKey(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for MeshKey {
    // Never print key material — only a short fingerprint for logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MeshKey({}…)", &self.to_hex()[..8])
    }
}

// ---------------------------------------------------------------------------
// Invite codes
// ---------------------------------------------------------------------------

/// Validate a miner id (also used for the `pool` label): only `[A-Za-z0-9_-]`,
/// 1..=64 chars. Rejects control chars (e.g. a newline that would corrupt logs)
/// and unbounded input before it is used, persisted, or logged.
pub fn valid_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Generate a high-entropy (256-bit) opaque invite code.
pub fn new_invite_code() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS CSPRNG unavailable");
    hex::encode(b)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InviteState {
    Issued,
    Consumed,
    Revoked,
}

#[derive(Clone, Debug)]
pub struct InviteRecord {
    pub code: String,
    pub pool: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub state: InviteState,
}

/// Store of issued invite codes. Single-use + expiring; `consume` flips an
/// `Issued` code to `Consumed` atomically so a code can enroll exactly one node.
#[derive(Default)]
pub struct InviteStore {
    invites: HashMap<String, InviteRecord>,
}

impl InviteStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ops issues a code to a pool with a TTL. Returns the code for handoff.
    pub fn issue(&mut self, code: String, pool: &str, now: u64, ttl_secs: u64) -> String {
        self.invites.insert(
            code.clone(),
            InviteRecord {
                code: code.clone(),
                pool: pool.to_string(),
                issued_at: now,
                expires_at: now.saturating_add(ttl_secs),
                state: InviteState::Issued,
            },
        );
        code
    }

    /// Non-mutating validity check. Returns the pool the code was issued to.
    /// Used before any other work so a bad *later* field never burns the invite.
    pub fn check(&self, code: &str, now: u64) -> Result<String, EnrollError> {
        let rec = self.invites.get(code).ok_or(EnrollError::UnknownInvite)?;
        match rec.state {
            InviteState::Revoked => return Err(EnrollError::InviteRevoked),
            InviteState::Consumed => return Err(EnrollError::InviteConsumed),
            InviteState::Issued => {}
        }
        if now >= rec.expires_at {
            return Err(EnrollError::InviteExpired);
        }
        Ok(rec.pool.clone())
    }

    /// Atomically consume a valid code. Errors identically to [`check`] and
    /// mutates only on success.
    pub fn consume(&mut self, code: &str, now: u64) -> Result<String, EnrollError> {
        let pool = self.check(code, now)?;
        // check() proved the entry exists and is Issued+unexpired.
        self.invites.get_mut(code).unwrap().state = InviteState::Consumed;
        Ok(pool)
    }

    pub fn revoke(&mut self, code: &str) -> bool {
        match self.invites.get_mut(code) {
            Some(rec) => {
                rec.state = InviteState::Revoked;
                true
            }
            None => false,
        }
    }

    pub fn state(&self, code: &str) -> Option<&InviteState> {
        self.invites.get(code).map(|r| &r.state)
    }
}

// ---------------------------------------------------------------------------
// Authorized-key store (what the relays read into RelayConfig.authorized_keys)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinerRecord {
    pub miner_id: String,
    pub key: [u8; 32],
    pub endpoint: SocketAddr,
    pub pool: String,
    pub revoked: bool,
}

/// The bridge to the mesh. `authorized_keys()` is exactly the `Vec<[u8;32]>` a
/// relay loads via `RelayConfig::with_authorized_keys` (`node.rs:138`), and
/// `peers()` is the fan-out endpoint set (§6). Revocation drops both.
#[derive(Default)]
pub struct KeyStore {
    miners: HashMap<String, MinerRecord>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a newly-enrolled miner. Rejects a second *active* registration
    /// for the same miner id (a revoked one may be re-registered).
    pub fn register(&mut self, rec: MinerRecord) -> Result<(), EnrollError> {
        if let Some(existing) = self.miners.get(&rec.miner_id)
            && !existing.revoked
        {
            return Err(EnrollError::DuplicateMiner);
        }
        self.miners.insert(rec.miner_id.clone(), rec);
        Ok(())
    }

    pub fn revoke(&mut self, miner_id: &str) -> bool {
        match self.miners.get_mut(miner_id) {
            Some(rec) => {
                rec.revoked = true;
                true
            }
            None => false,
        }
    }

    /// Active mesh keys — what the relay admits (`is_authorized`). Sorted for a
    /// stable on-disk render.
    pub fn authorized_keys(&self) -> Vec<[u8; 32]> {
        let mut keys: Vec<[u8; 32]> = self
            .miners
            .values()
            .filter(|m| !m.revoked)
            .map(|m| m.key)
            .collect();
        keys.sort_unstable();
        keys
    }

    /// Active peer endpoints — the relay fan-out set (§6).
    pub fn peers(&self) -> Vec<SocketAddr> {
        let mut p: Vec<SocketAddr> = self
            .miners
            .values()
            .filter(|m| !m.revoked)
            .map(|m| m.endpoint)
            .collect();
        p.sort_unstable();
        p
    }

    pub fn get(&self, miner_id: &str) -> Option<&MinerRecord> {
        self.miners.get(miner_id)
    }

    pub fn active_count(&self) -> usize {
        self.miners.values().filter(|m| !m.revoked).count()
    }
}

// ---------------------------------------------------------------------------
// Enrollment orchestration
// ---------------------------------------------------------------------------

/// Wire request a miner's node sends to the enroll service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub invite_code: String,
    pub miner_id: String,
    /// 32-byte mesh key, hex. Miner-generated.
    pub mesh_key_hex: String,
    /// The `ip:port` the miner's relay node will send/receive mesh traffic on.
    pub node_endpoint: String,
}

/// Wire response on success — what the node needs to connect to the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrollment {
    pub miner_id: String,
    pub pool: String,
    pub mesh_peers: Vec<String>,
}

/// The enroll transaction (§4 step 4). Order matters: every non-mutating check
/// runs **before** the invite is consumed, so a malformed key/endpoint or a
/// duplicate id returns an error **without** burning the miner's single-use
/// invite. Only when everything validates do we consume the invite and register
/// the key — the two mutations that must both happen (the caller holds the lock
/// spanning this call, so the pair is atomic for the PoC).
pub fn enroll(
    invites: &mut InviteStore,
    keys: &mut KeyStore,
    mesh_peers: &[SocketAddr],
    req: &EnrollRequest,
    now: u64,
) -> Result<Enrollment, EnrollError> {
    // 1. Non-mutating validation.
    invites.check(&req.invite_code, now)?; // 401/409, no mutation
    if !valid_ident(&req.miner_id) {
        return Err(EnrollError::BadMinerId); // 400, invite untouched
    }
    let key = MeshKey::from_hex(&req.mesh_key_hex)?; // 400
    let endpoint: SocketAddr = req
        .node_endpoint
        .trim()
        .parse()
        .map_err(|_| EnrollError::BadEndpoint)?; // 400
    if let Some(existing) = keys.get(&req.miner_id)
        && !existing.revoked
    {
        return Err(EnrollError::DuplicateMiner); // 409, invite untouched
    }

    // 2. Commit: consume the invite, then register the key. A consume failure
    // (e.g. a racing consumer spent it between check and here) must abort the
    // enroll — never register a key against an unspent/invalid invite.
    let pool = invites.consume(&req.invite_code, now)?;
    keys.register(MinerRecord {
        miner_id: req.miner_id.clone(),
        key: *key.as_bytes(),
        endpoint,
        pool: pool.clone(),
        revoked: false,
    })?;

    Ok(Enrollment {
        miner_id: req.miner_id.clone(),
        pool,
        mesh_peers: mesh_peers.iter().map(|p| p.to_string()).collect(),
    })
}

// ---------------------------------------------------------------------------
// Miner side
// ---------------------------------------------------------------------------

/// Miner-side bootstrap: generate a fresh mesh key and build the enroll request.
/// Returns the key (which the node persists locally to sign mesh traffic) and
/// the request (which it POSTs over TLS). The key's secret bytes leave the host
/// exactly once, inside this request, over the wire the caller must TLS-protect.
pub fn build_enroll_request(
    invite_code: &str,
    miner_id: &str,
    node_endpoint: &str,
) -> (MeshKey, EnrollRequest) {
    let key = MeshKey::generate();
    let req = EnrollRequest {
        invite_code: invite_code.to_string(),
        miner_id: miner_id.to_string(),
        mesh_key_hex: key.to_hex(),
        node_endpoint: node_endpoint.to_string(),
    };
    (key, req)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 3600;

    fn peers() -> Vec<SocketAddr> {
        vec![
            "10.0.0.1:9000".parse().unwrap(),
            "10.0.0.2:9000".parse().unwrap(),
        ]
    }

    // ---- MeshKey ----

    #[test]
    fn generate_is_nonzero_and_32_bytes() {
        let k = MeshKey::generate();
        assert_ne!(*k.as_bytes(), [0u8; 32]);
        assert_eq!(k.to_hex().len(), 64);
    }

    #[test]
    fn generate_produces_distinct_keys() {
        assert_ne!(MeshKey::generate().to_hex(), MeshKey::generate().to_hex());
    }

    #[test]
    fn from_hex_roundtrips() {
        let k = MeshKey::generate();
        let back = MeshKey::from_hex(&k.to_hex()).unwrap();
        assert_eq!(k, back);
    }

    #[test]
    fn from_hex_rejects_bad_input() {
        assert_eq!(
            MeshKey::from_hex("abcd").unwrap_err(),
            EnrollError::BadKeyLength
        );
        assert_eq!(
            MeshKey::from_hex(&"zz".repeat(32)).unwrap_err(),
            EnrollError::BadKeyHex
        );
        assert_eq!(
            MeshKey::from_hex(&"00".repeat(32)).unwrap_err(),
            EnrollError::ZeroKey
        );
    }

    #[test]
    fn debug_does_not_leak_full_key() {
        let k = MeshKey::from_hex(&"ab".repeat(32)).unwrap();
        let s = format!("{k:?}");
        assert!(
            !s.contains(&"ab".repeat(32)),
            "debug must not print full key"
        );
    }

    // ---- InviteStore ----

    #[test]
    fn invite_check_is_nonmutating_then_consume_is_single_use() {
        let mut s = InviteStore::new();
        let code = s.issue(new_invite_code(), "pool-a", 0, HOUR);
        // check twice — non-mutating.
        assert_eq!(s.check(&code, 1).unwrap(), "pool-a");
        assert_eq!(s.check(&code, 1).unwrap(), "pool-a");
        assert_eq!(*s.state(&code).unwrap(), InviteState::Issued);
        // consume once.
        assert_eq!(s.consume(&code, 1).unwrap(), "pool-a");
        assert_eq!(*s.state(&code).unwrap(), InviteState::Consumed);
        // second consume fails.
        assert_eq!(
            s.consume(&code, 1).unwrap_err(),
            EnrollError::InviteConsumed
        );
    }

    #[test]
    fn invite_unknown_expired_revoked() {
        let mut s = InviteStore::new();
        assert_eq!(s.check("nope", 0).unwrap_err(), EnrollError::UnknownInvite);

        let code = s.issue(new_invite_code(), "p", 0, HOUR);
        assert_eq!(
            s.check(&code, HOUR).unwrap_err(),
            EnrollError::InviteExpired
        );
        assert_eq!(
            s.consume(&code, HOUR).unwrap_err(),
            EnrollError::InviteExpired
        );

        let code2 = s.issue(new_invite_code(), "p", 0, HOUR);
        assert!(s.revoke(&code2));
        assert_eq!(s.check(&code2, 1).unwrap_err(), EnrollError::InviteRevoked);
    }

    // ---- KeyStore ----

    #[test]
    fn keystore_register_exposes_authorized_key_and_peer() {
        let mut ks = KeyStore::new();
        let key = MeshKey::from_hex(&"11".repeat(32)).unwrap();
        let ep: SocketAddr = "1.2.3.4:9000".parse().unwrap();
        ks.register(MinerRecord {
            miner_id: "m1".into(),
            key: *key.as_bytes(),
            endpoint: ep,
            pool: "p".into(),
            revoked: false,
        })
        .unwrap();
        assert_eq!(ks.authorized_keys(), vec![*key.as_bytes()]);
        assert_eq!(ks.peers(), vec![ep]);
        assert_eq!(ks.active_count(), 1);
    }

    #[test]
    fn keystore_duplicate_active_rejected_revoked_reusable() {
        let mut ks = KeyStore::new();
        let rec = |k: u8| MinerRecord {
            miner_id: "m1".into(),
            key: [k; 32],
            endpoint: "1.2.3.4:9000".parse().unwrap(),
            pool: "p".into(),
            revoked: false,
        };
        ks.register(rec(1)).unwrap();
        assert_eq!(
            ks.register(rec(2)).unwrap_err(),
            EnrollError::DuplicateMiner
        );
        // revoke drops the key from the mesh view...
        assert!(ks.revoke("m1"));
        assert!(ks.authorized_keys().is_empty());
        assert_eq!(ks.active_count(), 0);
        // ...and the id can be re-enrolled.
        ks.register(rec(3)).unwrap();
        assert_eq!(ks.authorized_keys(), vec![[3u8; 32]]);
    }

    // ---- enroll orchestration ----

    #[test]
    fn enroll_happy_path_adds_key_to_mesh() {
        let mut invites = InviteStore::new();
        let mut keys = KeyStore::new();
        let code = invites.issue(new_invite_code(), "pool-x", 0, HOUR);
        let (miner_key, req) = build_enroll_request(&code, "miner-1", "5.6.7.8:9000");

        let out = enroll(&mut invites, &mut keys, &peers(), &req, 1).unwrap();

        assert_eq!(out.miner_id, "miner-1");
        assert_eq!(out.pool, "pool-x");
        assert_eq!(out.mesh_peers.len(), 2);
        // The miner-generated key is now in the relay authorized-key set.
        assert_eq!(keys.authorized_keys(), vec![*miner_key.as_bytes()]);
        // Invite is spent.
        assert_eq!(*invites.state(&code).unwrap(), InviteState::Consumed);
    }

    #[test]
    fn enroll_bad_invite_does_not_touch_keystore() {
        let mut invites = InviteStore::new();
        let mut keys = KeyStore::new();
        let (_k, req) = build_enroll_request("no-such-code", "m", "5.6.7.8:9000");
        assert_eq!(
            enroll(&mut invites, &mut keys, &peers(), &req, 1).unwrap_err(),
            EnrollError::UnknownInvite
        );
        assert_eq!(keys.active_count(), 0);
    }

    #[test]
    fn enroll_bad_key_or_endpoint_does_not_burn_invite() {
        // A malformed later field must not consume the single-use invite.
        type ReqMut = fn(&mut EnrollRequest);
        let cases: [(&str, ReqMut); 2] = [
            ("key", |r| r.mesh_key_hex = "abcd".into()),
            ("endpoint", |r| r.node_endpoint = "not-an-addr".into()),
        ];
        for (bad_field, req_mut) in cases {
            let mut invites = InviteStore::new();
            let mut keys = KeyStore::new();
            let code = invites.issue(new_invite_code(), "pool-x", 0, HOUR);
            let (_k, mut req) = build_enroll_request(&code, "m", "5.6.7.8:9000");
            req_mut(&mut req);

            let err = enroll(&mut invites, &mut keys, &peers(), &req, 1).unwrap_err();
            assert_eq!(err.http_status(), 400, "bad {bad_field} -> 400");
            // Crucially: the invite survives for a corrected retry.
            assert_eq!(
                *invites.state(&code).unwrap(),
                InviteState::Issued,
                "bad {bad_field} must not burn the invite"
            );
            assert_eq!(keys.active_count(), 0);
        }
    }

    #[test]
    fn enroll_duplicate_miner_is_conflict_and_spares_second_invite() {
        let mut invites = InviteStore::new();
        let mut keys = KeyStore::new();
        let code1 = invites.issue(new_invite_code(), "pool-x", 0, HOUR);
        let (_k, req1) = build_enroll_request(&code1, "dup", "5.6.7.8:9000");
        enroll(&mut invites, &mut keys, &peers(), &req1, 1).unwrap();

        let code2 = invites.issue(new_invite_code(), "pool-y", 0, HOUR);
        let (_k2, req2) = build_enroll_request(&code2, "dup", "9.9.9.9:9000");
        let err = enroll(&mut invites, &mut keys, &peers(), &req2, 1).unwrap_err();
        assert_eq!(err, EnrollError::DuplicateMiner);
        assert_eq!(err.http_status(), 409);
        // Second invite not burned by the conflicting request.
        assert_eq!(*invites.state(&code2).unwrap(), InviteState::Issued);
        assert_eq!(keys.active_count(), 1);
    }

    #[test]
    fn enroll_rejects_bad_miner_id_without_burning_invite() {
        // A miner_id with a newline or over-length must be rejected (400) and
        // must not consume the single-use invite.
        for bad in ["evil\nid", &"x".repeat(65), "", "has space", "semi;colon"] {
            let mut invites = InviteStore::new();
            let mut keys = KeyStore::new();
            let code = invites.issue(new_invite_code(), "pool-x", 0, HOUR);
            let (_k, mut req) = build_enroll_request(&code, "placeholder", "5.6.7.8:9000");
            req.miner_id = bad.to_string();

            let err = enroll(&mut invites, &mut keys, &peers(), &req, 1).unwrap_err();
            assert_eq!(err, EnrollError::BadMinerId, "bad id {bad:?}");
            assert_eq!(err.http_status(), 400);
            assert_eq!(
                *invites.state(&code).unwrap(),
                InviteState::Issued,
                "bad miner_id must not burn the invite"
            );
            assert_eq!(keys.active_count(), 0);
        }
    }

    #[test]
    fn valid_ident_accepts_and_rejects() {
        assert!(valid_ident("miner-1"));
        assert!(valid_ident("Pool_Alpha-9"));
        assert!(valid_ident(&"a".repeat(64)));
        assert!(!valid_ident(""));
        assert!(!valid_ident(&"a".repeat(65)));
        assert!(!valid_ident("with\nnewline"));
        assert!(!valid_ident("with space"));
        assert!(!valid_ident("dots.not.ok"));
    }

    #[test]
    fn error_status_mapping() {
        assert_eq!(EnrollError::UnknownInvite.http_status(), 401);
        assert_eq!(EnrollError::InviteExpired.http_status(), 401);
        assert_eq!(EnrollError::InviteRevoked.http_status(), 401);
        assert_eq!(EnrollError::InviteConsumed.http_status(), 409);
        assert_eq!(EnrollError::DuplicateMiner.http_status(), 409);
        assert_eq!(EnrollError::ZeroKey.http_status(), 400);
    }
}
