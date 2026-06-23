# Settlement API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the pool an authenticated inbound control plane so the payout engine (sovright-api) can settle workers it has paid, re-keyed to worker name, so the durable payout state stays bounded.

**Architecture:** The pool's `PayoutTracker` is re-keyed from IP to worker name and gains explicit-total settlement semantics. A new hyper 0.14 control server exposes `POST /v1/settle` and `GET /v1/payouts` behind a bearer token. A scheduled prune in the maintenance loop archives and removes fully-settled, idle workers. sovright-api (separate repo, Part B / follow-up plan) calls `/v1/settle` after each confirmed payout.

**Tech Stack:** Rust, tokio, hyper 0.14 (already used by `sovright-telemetry`), serde/serde_json, prometheus.

## Global Constraints

- Conservative dependencies: this plan adds `hyper 0.14` and `serde_json` to `zcash-pool-server`. `hyper 0.14` is already a workspace dependency (`sovright-telemetry`); `serde_json` is workspace-ubiquitous. No other new deps. Implement constant-time token compare by hand (no `subtle` crate).
- Identity for durable credit and settlement is the **worker name** (`resolve_worker_label` output). Entries whose id begins with the reserved prefix `channel_` are **ephemeral/unnamed**: never settle-eligible, evicted on idle even under persistence.
- TDD: write the failing test first, watch it fail, implement, watch it pass, commit.
- Commit messages end with the repo's `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` trailer.
- All work in Part A targets the `bedrock` repo on branch `fix/durable-payout-state` (PR #56).

---

# Part A — Pool (bedrock repo)

## File Structure

- `crates/zcash-pool-common/src/payout.rs` — re-key helpers, settle semantics, prune gate, version bump (modify).
- `crates/zcash-pool-server/src/server.rs` — worker-name keying in the share handler; wire control server + scheduled prune (modify).
- `crates/zcash-pool-server/src/config.rs` — new config fields + validation (modify).
- `crates/zcash-pool-server/src/control.rs` — new hyper control server (create).
- `crates/zcash-pool-server/src/lib.rs` — register `control` module (modify).
- `crates/zcash-pool-server/Cargo.toml` — add `hyper`, `serde_json` (modify).

---

### Task A1: Reserved ephemeral-id helper

**Files:**
- Modify: `crates/zcash-pool-common/src/payout.rs`
- Test: same file, `#[cfg(test)] mod tests`

**Interfaces:**
- Produces: `pub fn is_ephemeral_miner_id(id: &str) -> bool`; `pub const EPHEMERAL_MINER_PREFIX: &str = "channel_";`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn ephemeral_id_detection() {
    assert!(is_ephemeral_miner_id("channel_42"));
    assert!(!is_ephemeral_miner_id("rig1"));
    assert!(!is_ephemeral_miner_id("worker.channel_1")); // only a prefix match counts
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p zcash-pool-common ephemeral_id_detection`
Expected: FAIL — `is_ephemeral_miner_id` not found.

- [ ] **Step 3: Implement**

Add near the top of `payout.rs` (after `pub type MinerId = String;`):

```rust
/// Reserved prefix marking an ephemeral, unnamed worker identity
/// (`resolve_worker_label` produces `channel_<id>` when no worker name was
/// supplied). Entries with this prefix are never settle-eligible and are
/// evicted on idle even when persistence is enabled.
pub const EPHEMERAL_MINER_PREFIX: &str = "channel_";

/// True if `id` is an ephemeral/unnamed worker identity (see
/// [`EPHEMERAL_MINER_PREFIX`]).
pub fn is_ephemeral_miner_id(id: &str) -> bool {
    id.starts_with(EPHEMERAL_MINER_PREFIX)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p zcash-pool-common ephemeral_id_detection`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/zcash-pool-common/src/payout.rs
git commit -m "feat(payout): reserved ephemeral worker-id helper"
```

---

### Task A2: Explicit-total settlement semantics

**Files:**
- Modify: `crates/zcash-pool-common/src/payout.rs` (`mark_miner_settled` at ~line 433)
- Test: same file

**Interfaces:**
- Produces: `pub struct SettleOutcome { pub total_shares: u64, pub settled_total_shares: u64 }` and
  `pub fn mark_miner_settled<S: Into<String>>(&self, miner_id: &MinerId, settled_total_shares: u64, settlement_ref: S) -> Option<SettleOutcome>`
- Consumes: `is_ephemeral_miner_id` (Task A1).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn settle_clamps_and_is_monotonic() {
    let t = PayoutTracker::new(Duration::from_secs(600));
    for _ in 0..10 { t.record_share(&"rig1".to_string(), 1.0); }

    // Clamp: cannot settle more than current total.
    let o = t.mark_miner_settled(&"rig1".to_string(), 999, "batch-1").unwrap();
    assert_eq!(o.total_shares, 10);
    assert_eq!(o.settled_total_shares, 10);

    // Monotonic: a lower explicit total never moves the watermark backward.
    let o = t.mark_miner_settled(&"rig1".to_string(), 3, "batch-2").unwrap();
    assert_eq!(o.settled_total_shares, 10);
}

#[test]
fn settle_unknown_or_ephemeral_returns_none() {
    let t = PayoutTracker::new(Duration::from_secs(600));
    assert!(t.mark_miner_settled(&"ghost".to_string(), 1, "b").is_none());
    t.record_share(&"channel_7".to_string(), 1.0);
    assert!(t.mark_miner_settled(&"channel_7".to_string(), 1, "b").is_none());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zcash-pool-common settle_`
Expected: FAIL — signature mismatch / `SettleOutcome` not found.

- [ ] **Step 3: Implement**

Add the struct near `SettlementState`:

```rust
/// Result of a successful settlement, returned for caller confirmation.
#[derive(Debug, Clone, Serialize)]
pub struct SettleOutcome {
    pub total_shares: u64,
    pub settled_total_shares: u64,
}
```

Replace the existing `mark_miner_settled` body with:

```rust
/// Record an explicit settlement watermark supplied by the payout engine.
///
/// The watermark is clamped to the worker's current `total_shares` (never
/// settle shares the pool has not credited) and is monotonic (never moves
/// backward), so repeated/retried calls are idempotent. Returns `None` for
/// unknown or ephemeral (unnamed) workers.
pub fn mark_miner_settled<S>(
    &self,
    miner_id: &MinerId,
    settled_total_shares: u64,
    settlement_ref: S,
) -> Option<SettleOutcome>
where
    S: Into<String>,
{
    if is_ephemeral_miner_id(miner_id) {
        return None;
    }

    let (current_total, current_difficulty) = {
        let miners = self.miners.read().unwrap_or_else(|e| e.into_inner());
        let stats = miners.get(miner_id)?;
        (stats.total_shares, stats.total_difficulty)
    };

    let now_unix_ms = unix_ms_now();
    let mut settlements = self.settlements.write().unwrap_or_else(|e| e.into_inner());
    let settlement = settlements.entry(miner_id.clone()).or_default();

    let clamped = settled_total_shares.min(current_total);
    let new_watermark = clamped.max(settlement.settled_total_shares);
    settlement.settled_total_shares = new_watermark;
    // Difficulty watermark tracks the current sum at the settled share count;
    // it is archived for audit but no longer gates pruning (see Task A3).
    settlement.settled_total_difficulty = current_difficulty;
    settlement.last_share_unix_ms.get_or_insert(now_unix_ms);
    settlement.settled_at_unix_ms = Some(now_unix_ms);
    settlement.settlement_ref = Some(settlement_ref.into());
    drop(settlements);

    self.mark_dirty();
    Some(SettleOutcome {
        total_shares: current_total,
        settled_total_shares: new_watermark,
    })
}
```

Update the two existing test call sites (`mark_miner_settled(&miner, "batch-1")`) to pass an explicit total, e.g. `mark_miner_settled(&miner, stats_total, "batch-1")` — read the worker's `total_shares` via `get_stats` first.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zcash-pool-common settle_ && cargo test -p zcash-pool-common`
Expected: PASS (all pool-common tests green).

- [ ] **Step 5: Commit**

```bash
git add crates/zcash-pool-common/src/payout.rs
git commit -m "feat(payout): explicit-total idempotent settlement watermark"
```

---

### Task A3: Prune on share-count equality + evict ephemeral under persistence

**Files:**
- Modify: `crates/zcash-pool-common/src/payout.rs` (`archive_record_if_prunable` ~646, `cleanup_stale_miners` ~487)
- Test: same file

**Interfaces:**
- Consumes: `is_ephemeral_miner_id` (A1), `mark_miner_settled` (A2).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn prune_gate_uses_share_count_not_difficulty() {
    let dir = std::env::temp_dir();
    let archive = dir.join(format!("settle-arch-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&archive);

    let t = PayoutTracker::new(Duration::from_secs(600));
    for _ in 0..5 { t.record_share(&"rig1".to_string(), 1.0); }
    // Settle the full current count; difficulty equality is irrelevant.
    t.mark_miner_settled(&"rig1".to_string(), 5, "batch-1").unwrap();

    let pruned = t.prune_settled_miners(Duration::ZERO, &archive).unwrap();
    assert_eq!(pruned, 1);
    assert!(t.get_stats(&"rig1".to_string()).is_none());
}

#[test]
fn cleanup_evicts_ephemeral_but_keeps_named_under_persistence() {
    let dir = std::env::temp_dir();
    let state = dir.join(format!("settle-state-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&state);
    let t = PayoutTracker::with_persistence(Duration::from_secs(600), &state).unwrap();

    t.record_share(&"rig1".to_string(), 1.0);
    t.record_share(&"channel_9".to_string(), 1.0);
    // Force both stale by clearing last_share via a long idle cleanup.
    std::thread::sleep(Duration::from_millis(5));
    t.cleanup_stale_miners(Duration::ZERO);

    assert!(t.get_stats(&"rig1".to_string()).is_some());   // named: retained
    assert!(t.get_stats(&"channel_9".to_string()).is_none()); // ephemeral: evicted
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zcash-pool-common prune_gate_uses_share_count_not_difficulty cleanup_evicts_ephemeral`
Expected: FAIL — difficulty gate blocks prune / ephemeral not evicted.

- [ ] **Step 3: Implement**

In `archive_record_if_prunable`, change the equality guard to share-count only:

```rust
    if settlement.settled_total_shares != stats.total_shares {
        return None;
    }
```

(Remove the `|| settlement.settled_total_difficulty != stats.total_difficulty` clause. The archive record still includes the difficulty fields.)

In `cleanup_stale_miners`, in the `persistence.is_some()` branch, evict stale ephemeral entries instead of only marking them inactive:

```rust
        if self.persistence.is_some() {
            let mut stale = 0;
            miners.retain(|id, stats| {
                let is_stale = stats.last_share.map(|t| t <= cutoff).unwrap_or(false);
                if is_stale && is_ephemeral_miner_id(id) {
                    stale += 1;
                    return false; // drop ephemeral/unnamed entries
                }
                if is_stale {
                    stats.window_shares = 0;
                    stats.window_difficulty = 0.0;
                    stats.last_share = None;
                    stale += 1;
                }
                true
            });
            drop(miners);
            if stale > 0 {
                let mut settlements =
                    self.settlements.write().unwrap_or_else(|e| e.into_inner());
                settlements.retain(|id, _| !is_ephemeral_miner_id(id));
                self.mark_dirty();
            }
            return stale;
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zcash-pool-common`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/zcash-pool-common/src/payout.rs
git commit -m "feat(payout): share-count prune gate; evict ephemeral workers"
```

---

### Task A4: State version bump

**Files:**
- Modify: `crates/zcash-pool-common/src/payout.rs` (`PAYOUT_STATE_VERSION` ~115)
- Test: same file

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn payout_state_version_is_two() {
    assert_eq!(PAYOUT_STATE_VERSION, 2);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p zcash-pool-common payout_state_version_is_two`
Expected: FAIL — value is 1.

- [ ] **Step 3: Implement**

```rust
const PAYOUT_STATE_VERSION: u32 = 2;
```

Confirm `load_persisted_state` already quarantines on version mismatch (it does — old v1 per-IP files are renamed aside and the pool starts clean).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p zcash-pool-common`
Expected: PASS (existing quarantine test still green).

- [ ] **Step 5: Commit**

```bash
git add crates/zcash-pool-common/src/payout.rs
git commit -m "feat(payout): bump state version to 2 (worker-name re-key)"
```

---

### Task A5: Re-key the share handler to worker name

**Files:**
- Modify: `crates/zcash-pool-server/src/server.rs` (miner_id derivation ~1234; share record ~1265)
- Test: `crates/zcash-pool-server/src/server.rs` `#[cfg(test)]` (or existing server test module)

**Interfaces:**
- Consumes: `resolve_worker_label(worker_identity: &Option<String>, channel_id: u32) -> String` (server.rs:155).

- [ ] **Step 1: Write the failing test**

Add a unit test asserting `resolve_worker_label` is what feeds payout credit. Since the share path is deep, test the keying decision directly:

```rust
#[test]
fn payout_keyed_by_worker_label_not_ip() {
    // Named worker -> worker name.
    assert_eq!(resolve_worker_label(&Some("rig1".to_string()), 42), "rig1");
    // Unnamed -> ephemeral channel id, which payout treats as non-durable.
    assert_eq!(resolve_worker_label(&None, 42), "channel_42");
    assert!(zcash_pool_common::is_ephemeral_miner_id(&resolve_worker_label(&None, 42)));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p zcash-pool-server payout_keyed_by_worker_label_not_ip`
Expected: FAIL if `is_ephemeral_miner_id` is not re-exported; otherwise compile error guides the fix.

- [ ] **Step 3: Implement**

Re-export the helper from pool-common in `crates/zcash-pool-common/src/lib.rs` (alongside `MinerId`):

```rust
pub use payout::{is_ephemeral_miner_id, EPHEMERAL_MINER_PREFIX};
```

In `server.rs`, replace the IP-based `miner_id` (lines 1234-1240) so credit is keyed by worker label. Move the derivation to where `channel.worker_identity` is in scope (inside the `channels.write()` block, just before the `try_record_share_once` call), and use:

```rust
let miner_id: MinerId = resolve_worker_label(&channel.worker_identity, channel_id);
```

Delete the now-unused `connection_times`-based IP derivation for `miner_id` (leave `connection_times` itself; other code uses it).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zcash-pool-server && cargo build -p zcash-pool-server`
Expected: PASS / clean build.

- [ ] **Step 5: Commit**

```bash
git add crates/zcash-pool-common/src/lib.rs crates/zcash-pool-server/src/server.rs
git commit -m "feat(pool): key payout credit by worker name, not IP"
```

---

### Task A6: Config fields + validation

**Files:**
- Modify: `crates/zcash-pool-server/src/config.rs`
- Test: same file `#[cfg(test)]`

**Interfaces:**
- Produces: `PoolConfig.control_addr: Option<SocketAddr>`, `control_auth_token: Option<String>`, `payout_settlement_retention: Duration`, `payout_archive_path: Option<PathBuf>`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn control_addr_requires_token() {
    let mut cfg = valid_config();
    cfg.control_addr = Some(SocketAddr::from(([127, 0, 0, 1], 9091)));
    cfg.control_auth_token = None;
    assert!(cfg.validate().is_err());

    cfg.control_auth_token = Some("secret".to_string());
    assert!(cfg.validate().is_ok());
}

#[test]
fn default_config_has_settlement_retention() {
    assert_eq!(valid_config().payout_settlement_retention, Duration::from_secs(86_400));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zcash-pool-server control_addr_requires_token default_config_has_settlement_retention`
Expected: FAIL — fields missing.

- [ ] **Step 3: Implement**

Add fields to `PoolConfig`:

```rust
    /// Optional bind address for the inbound settlement control plane.
    pub control_addr: Option<SocketAddr>,
    /// Bearer token required for control-plane requests. Required when
    /// `control_addr` is set.
    pub control_auth_token: Option<String>,
    /// How long a settled, idle worker is retained before pruning.
    pub payout_settlement_retention: Duration,
    /// Where pruned settlement records are archived (JSONL). Defaults next to
    /// `payout_state_path` when unset.
    pub payout_archive_path: Option<PathBuf>,
```

In the default/`valid_config` constructor set `control_addr: None`, `control_auth_token: None`, `payout_settlement_retention: Duration::from_secs(86_400)`, `payout_archive_path: None`.

In `validate()` add:

```rust
        if self.control_addr.is_some()
            && self
                .control_auth_token
                .as_ref()
                .map(|t| t.is_empty())
                .unwrap_or(true)
        {
            return Err(PoolError::Config(
                "control_addr set but control_auth_token is missing or empty".into(),
            ));
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zcash-pool-server config`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/zcash-pool-server/src/config.rs
git commit -m "feat(config): control-plane addr/token + settlement retention"
```

---

### Task A7: Control server module

**Files:**
- Create: `crates/zcash-pool-server/src/control.rs`
- Modify: `crates/zcash-pool-server/src/lib.rs` (add `pub mod control;`), `crates/zcash-pool-server/Cargo.toml` (add deps)
- Test: `crates/zcash-pool-server/src/control.rs` `#[cfg(test)]`

**Interfaces:**
- Produces: `pub async fn start_control_server(addr: SocketAddr, token: String, tracker: Arc<PayoutTracker>)`; request `SettleRequest { worker: String, settled_total_shares: u64, settlement_ref: String }`; helpers `fn token_matches(expected: &str, got: &str) -> bool`.
- Consumes: `PayoutTracker::mark_miner_settled` (A2), `get_all_stats`, `get_stats`.

- [ ] **Step 1: Add dependencies**

In `crates/zcash-pool-server/Cargo.toml` `[dependencies]`:

```toml
hyper = { version = "0.14", features = ["server", "tcp", "http1"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

- [ ] **Step 2: Write the failing tests**

```rust
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
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p zcash-pool-server -- control::tests`
Expected: FAIL — module/types not found.

- [ ] **Step 4: Implement `control.rs`**

```rust
//! Authenticated inbound control plane for settlement.
//!
//! Reuses the hyper 0.14 stack already used by the metrics server. Binds a
//! private address (operator default 127.0.0.1) and requires a bearer token.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

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
        return Ok(json(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#.into()));
    }

    match (req.method(), req.uri().path()) {
        (&Method::POST, "/v1/settle") => {
            let bytes = match hyper::body::to_bytes(req.into_body()).await {
                Ok(b) => b,
                Err(_) => return Ok(json(StatusCode::BAD_REQUEST, r#"{"error":"body"}"#.into())),
            };
            let parsed: Result<SettleRequest, _> = serde_json::from_slice(&bytes);
            let Ok(sr) = parsed else {
                return Ok(json(StatusCode::BAD_REQUEST, r#"{"error":"malformed"}"#.into()));
            };
            match tracker.mark_miner_settled(&sr.worker, sr.settled_total_shares, sr.settlement_ref) {
                Some(out) => Ok(json(
                    StatusCode::OK,
                    serde_json::to_string(&serde_json::json!({
                        "worker": sr.worker,
                        "total_shares": out.total_shares,
                        "settled_total_shares": out.settled_total_shares,
                    }))
                    .unwrap(),
                )),
                None => Ok(json(StatusCode::NOT_FOUND, r#"{"error":"unknown worker"}"#.into())),
            }
        }
        (&Method::GET, "/v1/payouts") => {
            let rows: Vec<PayoutRow> = tracker
                .payout_rows()
                .into_iter()
                .map(|(worker, total_shares, total_difficulty, settled, sref)| PayoutRow {
                    worker,
                    total_shares,
                    total_difficulty,
                    settled_total_shares: settled,
                    settlement_ref: sref,
                })
                .collect();
            Ok(json(StatusCode::OK, serde_json::to_string(&rows).unwrap()))
        }
        _ => Ok(json(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#.into())),
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
```

Add a read accessor to `PayoutTracker` in `payout.rs` for `/v1/payouts`:

```rust
/// Snapshot of per-worker totals + settlement watermark for reconciliation.
pub fn payout_rows(&self) -> Vec<(MinerId, u64, f64, u64, Option<String>)> {
    let miners = self.miners.read().unwrap_or_else(|e| e.into_inner());
    let settlements = self.settlements.read().unwrap_or_else(|e| e.into_inner());
    miners
        .iter()
        .map(|(id, s)| {
            let st = settlements.get(id);
            (
                id.clone(),
                s.total_shares,
                s.total_difficulty,
                st.map(|x| x.settled_total_shares).unwrap_or(0),
                st.and_then(|x| x.settlement_ref.clone()),
            )
        })
        .collect()
}
```

Add `pub mod control;` to `crates/zcash-pool-server/src/lib.rs`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p zcash-pool-server -- control::tests && cargo build -p zcash-pool-server`
Expected: PASS / clean build.

- [ ] **Step 6: Commit**

```bash
git add crates/zcash-pool-server/Cargo.toml crates/zcash-pool-server/src/control.rs crates/zcash-pool-server/src/lib.rs crates/zcash-pool-common/src/payout.rs Cargo.lock
git commit -m "feat(pool): hyper settlement control server (/v1/settle, /v1/payouts)"
```

---

### Task A8: Wire control server + scheduled prune into the server

**Files:**
- Modify: `crates/zcash-pool-server/src/server.rs` (spawn control server near metrics server ~363; add prune in maintenance loop ~457)
- Test: existing `cargo test -p zcash-pool-server` integration coverage; add a smoke test if a server harness exists.

**Interfaces:**
- Consumes: `control::start_control_server` (A7), `PayoutTracker::prune_settled_miners` (existing), config fields (A6).

- [ ] **Step 1: Spawn the control server**

Where the metrics server is started (`server.rs:363`), add:

```rust
        if let Some(control_addr) = self.config.control_addr {
            if let Some(token) = self.config.control_auth_token.clone() {
                let tracker = Arc::clone(&self.payout_tracker);
                tokio::spawn(async move {
                    crate::control::start_control_server(control_addr, token, tracker).await;
                });
            }
        }
```

- [ ] **Step 2: Add scheduled prune to the maintenance loop**

In the maintenance loop, right after the existing `payout_tracker.flush()` call (~457), add:

```rust
                let archive_path = self
                    .config
                    .payout_archive_path
                    .clone()
                    .or_else(|| {
                        self.config
                            .payout_state_path
                            .as_ref()
                            .map(|p| p.with_file_name("payout-archive.jsonl"))
                    });
                if let Some(archive_path) = archive_path {
                    match payout_tracker
                        .prune_settled_miners(self.config.payout_settlement_retention, &archive_path)
                    {
                        Ok(n) if n > 0 => info!("pruned {} settled miners", n),
                        Ok(_) => {}
                        Err(e) => error!("prune_settled_miners failed: {}", e),
                    }
                }
```

Note: this block references `self.config`; if the maintenance loop captured `payout_tracker` by clone without `self`, capture the needed config values into locals before the loop (mirror how `payout_tracker` is cloned at ~438).

- [ ] **Step 3: Build and run the full suite**

Run: `cargo build -p zcash-pool-server && cargo test -p zcash-pool-server`
Expected: clean build, tests PASS.

- [ ] **Step 4: Manual smoke test**

Run the pool with a control addr/token in a scratch config, then:

```bash
curl -s -XPOST localhost:9091/v1/settle \
  -H 'Authorization: Bearer secret' \
  -d '{"worker":"rig1","settled_total_shares":1,"settlement_ref":"manual"}'
curl -s localhost:9091/v1/payouts -H 'Authorization: Bearer secret'
curl -s -o /dev/null -w '%{http_code}\n' localhost:9091/v1/payouts   # expect 401
```

Expected: settle returns `200` (or `404` if rig1 has no shares yet), payouts returns JSON, unauthenticated returns `401`.

- [ ] **Step 5: Commit**

```bash
git add crates/zcash-pool-server/src/server.rs
git commit -m "feat(pool): start control server; schedule settled-miner prune"
```

---

### Task A9: Final verification + clippy/fmt

- [ ] **Step 1: Full workspace checks**

Run:
```bash
cargo fmt --all
cargo clippy --all-targets --features relay -- -D warnings
cargo test
```
Expected: fmt clean, clippy clean, all tests PASS.

- [ ] **Step 2: Commit any fmt/clippy fixups**

```bash
git add -A
git commit -m "chore(pool): fmt + clippy for settlement API"
```

- [ ] **Step 3: Push**

```bash
git push sovright fix/durable-payout-state
```

---

# Part B — sovright-api driver (Bedrock-product repo) — SEPARATE PLAN

Part B lives in a different git repo (`Bedrock-product/sovright-api`) and cannot be built or tested until Part A's control API exists and is deployed/mocked. It is therefore a **dependent follow-up plan** to be written once Part A lands. Below is the task outline and the single discovery item it must resolve first; turn this into its own `docs/.../plans/...-settlement-api-sovright.md` via the writing-plans skill at that time.

**Landmarks (verified):**
- Confirmation hook: `finalize_confirmed_job(pool, job_id, txid, operation_id, recipients)` at `src/payout/sweep.rs:652` (sets `payout_jobs.status = 'confirmed'`).
- Recipients: `payout_job_recipients` table (migration `20260310000000_shielded_payouts.sql`).
- Workers: `workers` table (`migrations/20260301000000_initial_schema.sql`), `share_events.worker_id`.
- HTTP: axum 0.8 + `reqwest` already present.

**Discovery task B0 (must run first):** Determine the exact mapping recipient → worker name → cumulative `shares_accepted` the payout paid through. Specifically: does a payout job recipient correspond to one worker, and where is the per-worker cumulative share counter that sovright-api ingested from the pool stored (it polls `shares_accepted_total{worker}`)? Output: the SQL/struct path from a confirmed job to `{worker_name, cumulative_shares_paid}`.

**Outline:**
- **B1. Pool control client** — `src/pool_control.rs`: reqwest wrapper for `POST /v1/settle` + `GET /v1/payouts`; base URL + token from config; bounded-backoff retry on 5xx/network; distinguish 401/404. TDD against a mock server (`wiremock` or a tiny axum test server — check existing test deps before adding).
- **B2. Settled-through persistence** — migration adding settlement tracking (e.g. `workers.settled_through_shares BIGINT` or a `pool_settlements` table) so settle calls are idempotent across retries/crashes.
- **B3. Settlement hook** — in `finalize_confirmed_job`, after status flips to `confirmed`, for each worker covered by the job call `/v1/settle` with `{worker, cumulative_shares_paid (from B0), settlement_ref = job_id/txid}`; persist settled-through (B2). Integration test: confirmed job → settle call with correct args.
- **B4. Operator surface** — surface settlement status (last settled total, ref) via the existing admin API/`dashboard.rs`; optional admin manual-settle endpoint calling B1.
- **B5. Config** — `POOL_CONTROL_URL`, `POOL_CONTROL_TOKEN` in `config.rs`.

---

## Self-Review Notes

- **Spec coverage:** P1→A4/A5; P2→A2/A3; P3→A7; P4→A6; wiring→A8; S1-S4→Part B outline. All Part A spec items map to a task.
- **Type consistency:** `mark_miner_settled` returns `Option<SettleOutcome>` (A2) and is consumed by control `/v1/settle` (A7). `payout_rows()` (A7) feeds `/v1/payouts`. `is_ephemeral_miner_id` defined A1, used A2/A3/A5. `SettleRequest` fields match the curl body and the spec contract.
- **Placeholder scan:** Part A contains complete code per step. Part B is explicitly a separate dependent plan with one named discovery task, not pretend-concrete tasks.
