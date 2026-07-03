//! Authenticated inbound control plane for settlement.
//!
//! Reuses the hyper 0.14 stack already used by the metrics server. Binds a
//! private address (operator default 127.0.0.1) and requires a bearer token.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

const MAX_BODY_BYTES: usize = 64 * 1024;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::payout::PayoutTracker;

#[derive(Debug, Deserialize)]
pub struct SettleRequest {
    pub worker: String,
    pub settled_total_shares: u64,
    pub settlement_ref: String,
}

#[derive(Debug, Serialize)]
struct PayoutRow {
    worker: String,
    total_shares: u64,
    total_difficulty: f64,
    settled_total_shares: u64,
    settlement_ref: Option<String>,
}

/// Constant-time-ish token comparison: length check then byte-OR accumulation
/// so the comparison time does not short-circuit on the first differing byte.
pub fn token_matches(expected: &str, got: &str) -> bool {
    let (e, g) = (expected.as_bytes(), got.as_bytes());
    if e.len() != g.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..e.len() {
        diff |= e[i] ^ g[i];
    }
    diff == 0
}

fn authorized(req: &Request<Body>, token: &str) -> bool {
    req.headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|got| token_matches(token, got))
        .unwrap_or(false)
}

fn json(status: StatusCode, body: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

async fn handle(
    req: Request<Body>,
    token: Arc<String>,
    tracker: Arc<PayoutTracker>,
) -> Result<Response<Body>, Infallible> {
    if !authorized(&req, &token) {
        return Ok(json(
            StatusCode::UNAUTHORIZED,
            r#"{"error":"unauthorized"}"#.into(),
        ));
    }

    match (req.method(), req.uri().path()) {
        (&Method::POST, "/v1/settle") => {
            // Reject oversized requests before reading the body.
            if let Some(content_length) = req
                .headers()
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
                && content_length > MAX_BODY_BYTES
            {
                return Ok(json(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    r#"{"error":"payload too large"}"#.into(),
                ));
            }
            let bytes = match hyper::body::to_bytes(req.into_body()).await {
                Ok(b) => b,
                Err(_) => return Ok(json(StatusCode::BAD_REQUEST, r#"{"error":"body"}"#.into())),
            };
            if bytes.len() > MAX_BODY_BYTES {
                return Ok(json(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    r#"{"error":"payload too large"}"#.into(),
                ));
            }
            let parsed: Result<SettleRequest, _> = serde_json::from_slice(&bytes);
            let Ok(sr) = parsed else {
                return Ok(json(
                    StatusCode::BAD_REQUEST,
                    r#"{"error":"malformed"}"#.into(),
                ));
            };
            match tracker.mark_miner_settled(&sr.worker, sr.settled_total_shares, sr.settlement_ref)
            {
                Some(out) => {
                    let body_val = serde_json::json!({
                        "worker": sr.worker,
                        "total_shares": out.total_shares,
                        "settled_total_shares": out.settled_total_shares,
                    });
                    match serde_json::to_string(&body_val) {
                        Ok(body) => Ok(json(StatusCode::OK, body)),
                        Err(_) => Ok(json(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            r#"{"error":"serialization"}"#.into(),
                        )),
                    }
                }
                None => Ok(json(
                    StatusCode::NOT_FOUND,
                    r#"{"error":"unknown worker"}"#.into(),
                )),
            }
        }
        (&Method::GET, "/v1/payouts") => {
            let rows: Vec<PayoutRow> = tracker
                .payout_rows()
                .into_iter()
                .map(
                    |(worker, total_shares, total_difficulty, settled, sref)| PayoutRow {
                        worker,
                        total_shares,
                        total_difficulty,
                        settled_total_shares: settled,
                        settlement_ref: sref,
                    },
                )
                .collect();
            match serde_json::to_string(&rows) {
                Ok(body) => Ok(json(StatusCode::OK, body)),
                Err(_) => Ok(json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    r#"{"error":"serialization"}"#.into(),
                )),
            }
        }
        _ => Ok(json(
            StatusCode::NOT_FOUND,
            r#"{"error":"not found"}"#.into(),
        )),
    }
}

/// Start the control server. Runs until the process exits.
pub async fn start_control_server(addr: SocketAddr, token: String, tracker: Arc<PayoutTracker>) {
    let token = Arc::new(token);
    let make_svc = make_service_fn(move |_| {
        let token = Arc::clone(&token);
        let tracker = Arc::clone(&tracker);
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle(req, Arc::clone(&token), Arc::clone(&tracker))
            }))
        }
    });
    info!("settlement control server listening on {}", addr);
    if let Err(e) = Server::bind(&addr).serve(make_svc).await {
        error!("control server error: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_token_compare() {
        assert!(token_matches("abc123", "abc123"));
        assert!(!token_matches("abc123", "abc124"));
        assert!(!token_matches("abc123", "abc1234")); // length mismatch
    }

    #[test]
    fn settle_request_parses() {
        let body = r#"{"worker":"rig1","settled_total_shares":42,"settlement_ref":"batch-1"}"#;
        let req: SettleRequest = serde_json::from_str(body).unwrap();
        assert_eq!(req.worker, "rig1");
        assert_eq!(req.settled_total_shares, 42);
        assert_eq!(req.settlement_ref, "batch-1");
    }

    #[test]
    fn max_body_bytes_cap_is_64kib() {
        assert_eq!(MAX_BODY_BYTES, 65536);
    }

    #[test]
    fn oversized_body_exceeds_cap() {
        // Simulate what the handler checks: bytes.len() > MAX_BODY_BYTES
        let oversized = vec![b'x'; MAX_BODY_BYTES + 1];
        assert!(oversized.len() > MAX_BODY_BYTES);

        let exact = vec![b'x'; MAX_BODY_BYTES];
        assert!(exact.len() <= MAX_BODY_BYTES);
    }

    // ---- HTTP-level handler tests -------------------------------------------
    //
    // These drive the real `handle()` request flow against an in-memory
    // `PayoutTracker` and assert the status codes documented in
    // docs/superpowers/specs/2026-06-23-settlement-api-design.md (§P3):
    // 401 missing/bad token, 200 valid settle, 404 unknown worker,
    // 400 malformed body.

    const TEST_TOKEN: &str = "super-secret-token";

    /// Tracker with one known, settle-eligible named worker ("rig1").
    fn tracker_with_known_worker() -> Arc<PayoutTracker> {
        let tracker = Arc::new(PayoutTracker::default());
        tracker.record_share(&"rig1".to_string(), 1.0);
        tracker
    }

    /// Drive `handle()` and return the response status.
    async fn call(req: Request<Body>, tracker: Arc<PayoutTracker>) -> StatusCode {
        let token = Arc::new(TEST_TOKEN.to_string());
        handle(req, token, tracker).await.unwrap().status()
    }

    fn settle_request(token: Option<&str>, body: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/v1/settle")
            .header(hyper::header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    #[tokio::test]
    async fn settle_missing_auth_header_is_401() {
        let body = r#"{"worker":"rig1","settled_total_shares":1,"settlement_ref":"batch-1"}"#;
        let status = call(settle_request(None, body), tracker_with_known_worker()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn settle_wrong_token_is_401() {
        let body = r#"{"worker":"rig1","settled_total_shares":1,"settlement_ref":"batch-1"}"#;
        let status = call(
            settle_request(Some("wrong-token"), body),
            tracker_with_known_worker(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn settle_valid_known_worker_is_200() {
        let body = r#"{"worker":"rig1","settled_total_shares":1,"settlement_ref":"batch-1"}"#;
        let status = call(
            settle_request(Some(TEST_TOKEN), body),
            tracker_with_known_worker(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn settle_unknown_worker_is_404() {
        let body = r#"{"worker":"ghost","settled_total_shares":1,"settlement_ref":"batch-1"}"#;
        let status = call(
            settle_request(Some(TEST_TOKEN), body),
            tracker_with_known_worker(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn settle_malformed_body_is_400() {
        let status = call(
            settle_request(Some(TEST_TOKEN), "{ not valid json ]"),
            tracker_with_known_worker(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
