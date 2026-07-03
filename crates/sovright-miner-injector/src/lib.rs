//! sovright-miner-injector (PoC) — miner-side client for direct block injection.
//!
//! This is the **Phase 3 proof-of-concept** described in
//! `docs/miner-direct-injection.md`. When a pool/miner finds a block, instead of
//! waiting for native Zcash P2P gossip to carry it, it POSTs the full serialized
//! block to the nearest relay's *block injection endpoint*. The relay validates
//! the Equihash PoW and floods it across the inter-region mesh so every region's
//! Zebra receives it via `submitblock` before gossip arrives.
//!
//! This crate implements ONLY the miner side. It builds an authenticated HTTP/1.1
//! request and (optionally) sends it over a plain `std::net::TcpStream`. The
//! relay-side endpoint is stubbed/documented, not implemented here.
//!
//! ## Wire protocol (front door)
//!
//! `POST {path} HTTP/1.1` with `Content-Type: application/octet-stream` and body =
//! the raw serialized Zcash block bytes. Authentication headers:
//!
//! - `X-Sovright-Miner-Id`:  opaque miner/pool identifier (selects the key server-side)
//! - `X-Sovright-Timestamp`: unix seconds, for the replay window
//! - `X-Sovright-Nonce`:     16 random bytes, hex, for replay dedup
//! - `X-Sovright-Auth`:      hex HMAC-SHA256 over the canonical signing preimage
//!
//! The MAC covers miner id, timestamp, nonce, body length, AND the full body, so
//! the relay authenticates the exact bytes it is about to flood. HMAC-SHA256 with
//! a 32-byte per-miner key mirrors the relay mesh's own chunk auth
//! (`sovright-relay/src/transport/session.rs`).

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Auth header names, kept as constants so the relay side can match verbatim.
pub const HDR_MINER_ID: &str = "X-Sovright-Miner-Id";
pub const HDR_TIMESTAMP: &str = "X-Sovright-Timestamp";
pub const HDR_NONCE: &str = "X-Sovright-Nonce";
pub const HDR_AUTH: &str = "X-Sovright-Auth";

/// Default injection path on the relay.
pub const DEFAULT_INJECT_PATH: &str = "/v1/inject/block";

/// Errors constructing or sending an injection request.
#[derive(Debug)]
pub enum InjectError {
    /// The auth key was not exactly 32 bytes.
    BadKeyLength(usize),
    /// The block body was empty.
    EmptyBlock,
    /// I/O failure talking to the relay.
    Io(std::io::Error),
    /// The relay returned a non-2xx status line.
    RelayRejected { status: u16, body: String },
    /// The response could not be parsed as HTTP/1.1.
    MalformedResponse,
}

impl std::fmt::Display for InjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InjectError::BadKeyLength(n) => {
                write!(f, "auth key must be 32 bytes, got {n}")
            }
            InjectError::EmptyBlock => write!(f, "block body is empty"),
            InjectError::Io(e) => write!(f, "io error: {e}"),
            InjectError::RelayRejected { status, body } => {
                write!(f, "relay rejected injection: status={status} body={body}")
            }
            InjectError::MalformedResponse => write!(f, "malformed HTTP response from relay"),
        }
    }
}

impl std::error::Error for InjectError {}

impl From<std::io::Error> for InjectError {
    fn from(e: std::io::Error) -> Self {
        InjectError::Io(e)
    }
}

/// Everything needed to authenticate a single injection.
#[derive(Clone)]
pub struct MinerCredentials {
    /// Opaque miner/pool id; selects the key on the relay side.
    pub miner_id: String,
    /// 32-byte shared secret. Per-miner; never leaves the miner and relay.
    pub key: [u8; 32],
}

impl MinerCredentials {
    /// Build credentials from a hex-encoded 32-byte key.
    pub fn from_hex_key(miner_id: impl Into<String>, key_hex: &str) -> Result<Self, InjectError> {
        let bytes = hex::decode(key_hex.trim()).map_err(|_| InjectError::BadKeyLength(0))?;
        if bytes.len() != 32 {
            return Err(InjectError::BadKeyLength(bytes.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self {
            miner_id: miner_id.into(),
            key,
        })
    }
}

/// A fully-constructed, signed injection request ready to serialize to the wire.
///
/// Separating construction from I/O makes the auth logic unit-testable without a
/// socket (see the tests at the bottom of this file).
pub struct InjectionRequest {
    pub host: String,
    pub path: String,
    pub miner_id: String,
    pub timestamp: u64,
    pub nonce: [u8; 16],
    /// Raw serialized block bytes — exactly what the relay will flood.
    pub body: Vec<u8>,
    /// hex HMAC-SHA256 over the canonical preimage.
    pub auth_hex: String,
}

/// Compute the canonical signing preimage.
///
/// Order is fixed and length-delimited so no field boundary is ambiguous:
/// `miner_id \n timestamp \n nonce_hex \n body_len \n` followed by the raw body.
/// The relay MUST reconstruct this exact preimage to verify.
pub fn signing_preimage(
    miner_id: &str,
    timestamp: u64,
    nonce: &[u8; 16],
    body: &[u8],
) -> Vec<u8> {
    let mut pre = Vec::with_capacity(miner_id.len() + 64 + body.len());
    pre.extend_from_slice(miner_id.as_bytes());
    pre.push(b'\n');
    pre.extend_from_slice(timestamp.to_string().as_bytes());
    pre.push(b'\n');
    pre.extend_from_slice(hex::encode(nonce).as_bytes());
    pre.push(b'\n');
    pre.extend_from_slice(body.len().to_string().as_bytes());
    pre.push(b'\n');
    pre.extend_from_slice(body);
    pre
}

/// Compute the hex HMAC-SHA256 auth tag for a request.
pub fn compute_auth(
    key: &[u8; 32],
    miner_id: &str,
    timestamp: u64,
    nonce: &[u8; 16],
    body: &[u8],
) -> String {
    let preimage = signing_preimage(miner_id, timestamp, nonce, body);
    let mut mac =
        HmacSha256::new_from_slice(key).expect("32-byte key is always valid for HMAC-SHA256");
    mac.update(&preimage);
    hex::encode(mac.finalize().into_bytes())
}

impl InjectionRequest {
    /// Build and sign an injection request. `timestamp` and `nonce` are injected
    /// (rather than sampled internally) so tests are deterministic; the CLI fills
    /// them from the clock and OS entropy.
    pub fn build(
        creds: &MinerCredentials,
        host: impl Into<String>,
        path: impl Into<String>,
        timestamp: u64,
        nonce: [u8; 16],
        body: Vec<u8>,
    ) -> Result<Self, InjectError> {
        if body.is_empty() {
            return Err(InjectError::EmptyBlock);
        }
        let miner_id = creds.miner_id.clone();
        let auth_hex = compute_auth(&creds.key, &miner_id, timestamp, &nonce, &body);
        Ok(Self {
            host: host.into(),
            path: path.into(),
            miner_id,
            timestamp,
            nonce,
            body,
            auth_hex,
        })
    }

    /// Serialize the request to raw HTTP/1.1 bytes (headers + body).
    pub fn to_http_bytes(&self) -> Vec<u8> {
        let head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\
             {h_id}: {miner_id}\r\n\
             {h_ts}: {ts}\r\n\
             {h_nonce}: {nonce}\r\n\
             {h_auth}: {auth}\r\n\
             \r\n",
            path = self.path,
            host = self.host,
            len = self.body.len(),
            h_id = HDR_MINER_ID,
            miner_id = self.miner_id,
            h_ts = HDR_TIMESTAMP,
            ts = self.timestamp,
            h_nonce = HDR_NONCE,
            nonce = hex::encode(self.nonce),
            h_auth = HDR_AUTH,
            auth = self.auth_hex,
        );
        let mut out = head.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }

    /// Send the request over a plain TCP connection to `addr` (e.g. "10.0.0.1:8645")
    /// and return the relay's response body on 2xx.
    ///
    /// PoC transport: plaintext HTTP over `std::net::TcpStream`. Production would
    /// use TLS (see design doc §Transport). No new dependency is pulled in for the
    /// PoC; a TLS wrapper (rustls) is a documented follow-up.
    pub fn send_tcp(&self, addr: &str) -> Result<String, InjectError> {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(addr)?;
        stream.write_all(&self.to_http_bytes())?;
        stream.flush()?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw)?;
        parse_http_response(&raw)
    }
}

/// Minimal HTTP/1.1 response parser: returns Ok(body) for 2xx, else RelayRejected.
fn parse_http_response(raw: &[u8]) -> Result<String, InjectError> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or(InjectError::MalformedResponse)?;
    // "HTTP/1.1 200 OK"
    let mut parts = status_line.split_whitespace();
    let _version = parts.next().ok_or(InjectError::MalformedResponse)?;
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or(InjectError::MalformedResponse)?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    if (200..300).contains(&status) {
        Ok(body)
    } else {
        Err(InjectError::RelayRejected { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_creds() -> MinerCredentials {
        // Deterministic 32-byte key: 0x01,0x02,...,0x20
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        MinerCredentials {
            miner_id: "pool-alpha".to_string(),
            key,
        }
    }

    #[test]
    fn from_hex_key_rejects_wrong_length() {
        assert!(matches!(
            MinerCredentials::from_hex_key("m", "abcd"),
            Err(InjectError::BadKeyLength(2))
        ));
    }

    #[test]
    fn from_hex_key_accepts_32_bytes() {
        let hexkey = "01".repeat(32);
        let creds = MinerCredentials::from_hex_key("m", &hexkey).unwrap();
        assert_eq!(creds.key, [1u8; 32]);
    }

    #[test]
    fn auth_is_deterministic_known_vector() {
        // Locks the signing scheme so a relay-side verifier can be checked
        // against the same vector. If this value changes, the wire protocol
        // changed and both sides must be updated in lockstep.
        let creds = fixed_creds();
        let nonce = [0xAAu8; 16];
        let body = b"serialized-block-bytes".to_vec();
        let auth = compute_auth(&creds.key, &creds.miner_id, 1_700_000_000, &nonce, &body);
        assert_eq!(
            auth,
            "234313eae67f00382b39655e9c9aa0229043b947837a28349375fe86ee3c9da0",
            "auth vector drifted; regenerate intentionally, not by accident"
        );
    }

    #[test]
    fn body_tampering_changes_auth() {
        let creds = fixed_creds();
        let nonce = [0u8; 16];
        let a = compute_auth(&creds.key, &creds.miner_id, 42, &nonce, b"block-A");
        let b = compute_auth(&creds.key, &creds.miner_id, 42, &nonce, b"block-B");
        assert_ne!(a, b, "MAC must cover the body");
    }

    #[test]
    fn nonce_and_timestamp_bound_into_auth() {
        let creds = fixed_creds();
        let body = b"same-block".to_vec();
        let base = compute_auth(&creds.key, &creds.miner_id, 100, &[0u8; 16], &body);
        let diff_ts = compute_auth(&creds.key, &creds.miner_id, 101, &[0u8; 16], &body);
        let diff_nonce = compute_auth(&creds.key, &creds.miner_id, 100, &[1u8; 16], &body);
        assert_ne!(base, diff_ts, "timestamp must be authenticated");
        assert_ne!(base, diff_nonce, "nonce must be authenticated");
    }

    #[test]
    fn build_rejects_empty_block() {
        let creds = fixed_creds();
        let err = InjectionRequest::build(&creds, "h", "/p", 1, [0u8; 16], vec![]);
        assert!(matches!(err, Err(InjectError::EmptyBlock)));
    }

    #[test]
    fn http_bytes_contain_all_auth_headers_and_body() {
        let creds = fixed_creds();
        let body = b"\x00\x01\x02block".to_vec();
        let req = InjectionRequest::build(
            &creds,
            "relay.example:8645",
            DEFAULT_INJECT_PATH,
            1_700_000_000,
            [0xAB; 16],
            body.clone(),
        )
        .unwrap();
        let bytes = req.to_http_bytes();
        let text = String::from_utf8_lossy(&bytes);

        assert!(text.starts_with("POST /v1/inject/block HTTP/1.1\r\n"));
        assert!(text.contains("Host: relay.example:8645\r\n"));
        assert!(text.contains("Content-Type: application/octet-stream\r\n"));
        assert!(text.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(text.contains(&format!("{HDR_MINER_ID}: pool-alpha\r\n")));
        assert!(text.contains(&format!("{HDR_TIMESTAMP}: 1700000000\r\n")));
        assert!(text.contains(&format!("{HDR_NONCE}: {}\r\n", hex::encode([0xABu8; 16]))));
        assert!(text.contains(&format!("{HDR_AUTH}: {}\r\n", req.auth_hex)));
        // Body is appended verbatim after the blank line.
        assert!(bytes.ends_with(&body));
    }

    #[test]
    fn parse_response_accepts_2xx_and_rejects_others() {
        let ok = b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\n\r\nok";
        assert_eq!(parse_http_response(ok).unwrap(), "ok");

        let bad = b"HTTP/1.1 401 Unauthorized\r\n\r\nbad auth";
        match parse_http_response(bad) {
            Err(InjectError::RelayRejected { status, body }) => {
                assert_eq!(status, 401);
                assert_eq!(body, "bad auth");
            }
            other => panic!("expected RelayRejected, got {other:?}"),
        }
    }
}
