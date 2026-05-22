# P2P First-Block Portfolio Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add measurement-only peer telemetry and fleet scorecard support so Bedrock can rank Zcash P2P peers by first-block discovery value before enabling any connection rotation.

**Architecture:** `bedrock-p2p-ingress` keeps its current crawler behavior and emits additional timing events from each peer task. The private deployment repo consumes existing observer JSONL logs plus the new timing events to build an advisory `(observer, peer)` scorecard. No runtime connection policy changes are enabled in this phase.

**Tech Stack:** Rust 2024, Tokio, JSONL telemetry, Python 3 operator scripts, existing GCP/IAP log collection.

---

## File Structure

- Modify `crates/bedrock-p2p-ingress/src/event.rs`: add structured event methods for connect timing, handshake timing, ping RTT, and advisory peer score telemetry.
- Modify `crates/bedrock-p2p-ingress/src/peer.rs`: measure TCP connect latency, handshake latency, send a post-handshake `ping`, record matching `pong` RTT, and log timings without changing block request behavior.
- Modify `crates/bedrock-p2p-ingress/README.md`: document new measurement events and clarify that rotation remains disabled.
- Create `/private/tmp/bedrock-mainnet-deployment/scripts/p2p/summarize_peer_scorecard.py`: advisory fleet scorecard over observer logs.
- Modify `/private/tmp/bedrock-mainnet-deployment/runbooks/zcash-p2p-ingress.md`: document new timing events and the scorecard command.
- Modify `/private/tmp/bedrock-mainnet-deployment/docs/current-state.md` and `/private/tmp/bedrock-mainnet-deployment/docs/deployment-log.md` only after deployment verification.

## Task 1: Event Sink Timing Methods

**Files:**
- Modify: `crates/bedrock-p2p-ingress/src/event.rs`

- [ ] **Step 1: Add event methods**

Add these methods to `impl EventSink` after `p2p_peer_connected`:

```rust
    pub fn p2p_connect_timing(&self, peer: &str, connect_ms: u128) -> Result<()> {
        self.write(json!({
            "event": "p2p_connect_timing",
            "peer": peer,
            "connect_ms": connect_ms,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_handshake_timing(&self, peer: &str, handshake_ms: u128) -> Result<()> {
        self.write(json!({
            "event": "p2p_handshake_timing",
            "peer": peer,
            "handshake_ms": handshake_ms,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_ping_rtt(&self, peer: &str, nonce: u64, rtt_ms: u128) -> Result<()> {
        self.write(json!({
            "event": "p2p_ping_rtt",
            "peer": peer,
            "nonce": nonce,
            "rtt_ms": rtt_ms,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }

    pub fn p2p_peer_score(&self, peer: &str, score: i64, reason: &str) -> Result<()> {
        self.write(json!({
            "event": "p2p_peer_score",
            "peer": peer,
            "score": score,
            "reason": reason,
            "observed_at_unix_ms": now_unix_ms(),
        }))
    }
```

- [ ] **Step 2: Format and test compile**

Run:

```bash
cargo fmt --package bedrock-p2p-ingress
cargo test -p bedrock-p2p-ingress
```

Expected: all existing tests pass.

## Task 2: Peer Timing Instrumentation

**Files:**
- Modify: `crates/bedrock-p2p-ingress/src/peer.rs`

- [ ] **Step 1: Add `Instant` import**

Change:

```rust
use std::time::{Duration, SystemTime, UNIX_EPOCH};
```

to:

```rust
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
```

- [ ] **Step 2: Measure TCP connect latency**

Replace the current `TcpStream::connect` block with:

```rust
    let connect_started = Instant::now();
    let stream = timeout(config.connect_timeout, TcpStream::connect(peer_addr))
        .await
        .map_err(|_| IngressError::Timeout(format!("connect to {peer}")))??;
    events.p2p_connect_timing(&peer, connect_started.elapsed().as_millis())?;
```

Keep the existing `stream.set_nodelay(true)?;` and `events.p2p_peer_connected(&peer)?;` lines immediately after.

- [ ] **Step 3: Track handshake and ping timing state**

After `let mut sent_verack = false;`, add:

```rust
    let handshake_started = Instant::now();
    let mut ping_nonce = None;
    let mut ping_started = None;
```

- [ ] **Step 4: Emit handshake timing and send one post-handshake ping**

Inside the `"verack"` match arm, after `events.p2p_handshake_complete(&peer)?;`, add:

```rust
                events.p2p_handshake_timing(&peer, handshake_started.elapsed().as_millis())?;
                let nonce = nonce();
                write_message(&mut writer, "ping", &nonce.to_le_bytes()).await?;
                ping_nonce = Some(nonce);
                ping_started = Some(Instant::now());
```

Keep `write_message(&mut writer, "getaddr", &[]).await?;` after the ping setup.

- [ ] **Step 5: Handle matching pong RTT**

Add this match arm before `"ping"`:

```rust
            "pong" => {
                if msg.payload.len() == 8 {
                    let nonce = u64::from_le_bytes(msg.payload[..8].try_into().expect("slice length"));
                    if Some(nonce) == ping_nonce {
                        if let Some(started) = ping_started.take() {
                            events.p2p_ping_rtt(&peer, nonce, started.elapsed().as_millis())?;
                        }
                        ping_nonce = None;
                    }
                }
            }
```

- [ ] **Step 6: Extract pong nonce helper and add unit test**

Add this helper near `remote_version`:

```rust
fn pong_nonce(payload: &[u8]) -> Option<u64> {
    if payload.len() == 8 {
        Some(u64::from_le_bytes(payload.try_into().ok()?))
    } else {
        None
    }
}
```

And add this test:

```rust
    #[test]
    fn parses_pong_nonce() {
        let nonce = 42u64;
        assert_eq!(pong_nonce(&nonce.to_le_bytes()), Some(42));
        assert_eq!(pong_nonce(&[1, 2, 3]), None);
    }
```

- [ ] **Step 7: Verify**

Run:

```bash
cargo fmt --package bedrock-p2p-ingress
cargo test -p bedrock-p2p-ingress
```

Expected: all tests pass.

Commit:

```bash
git add crates/bedrock-p2p-ingress/src/event.rs crates/bedrock-p2p-ingress/src/peer.rs crates/bedrock-p2p-ingress/README.md
git commit -m "Add P2P peer timing telemetry"
```

## Task 3: README Documentation

**Files:**
- Modify: `crates/bedrock-p2p-ingress/README.md`

- [ ] **Step 1: Add measurement event list**

Append this paragraph after the crawler-mode paragraph:

```markdown
Measurement events include `p2p_connect_timing`, `p2p_handshake_timing`,
`p2p_ping_rtt`, `p2p_block_inv`, `p2p_getdata_sent`, and
`p2p_block_received`. These events are advisory telemetry only; crawler mode
does not rotate connections by score yet.
```

- [ ] **Step 2: Verify docs and tests**

Run:

```bash
cargo test -p bedrock-p2p-ingress
```

Expected: all tests pass.

## Task 4: Advisory Peer Scorecard Script

**Files:**
- Create: `/private/tmp/bedrock-mainnet-deployment/scripts/p2p/summarize_peer_scorecard.py`

- [ ] **Step 1: Add script**

Create a Python script that reuses the existing GCP tail pattern from `scripts/p2p/summarize_crawler_events.py`, parses JSONL rows, and emits a table with:

```text
observer peer score first_blocks top2_blocks top3_blocks blocks invs avg_getdata_to_recv_ms avg_ping_rtt_ms errors
```

Scoring constants:

```python
FIRST_BLOCK_POINTS = 100
TOP2_BLOCK_POINTS = 50
TOP3_BLOCK_POINTS = 25
BLOCK_POINTS = 10
INV_POINTS = 5
HANDSHAKE_POINTS = 2
ERROR_POINTS = -10
```

The script implementation must:

- group block receive observations by hash
- sort each block's observations by `observed_at_unix_ms`
- award first/top2/top3 points to `(observer, peer)`
- award block, inventory, handshake, and error points independently
- compute average `p2p_getdata_sent` to `p2p_block_received` delta for matching `(observer, peer, hash)`
- compute average `p2p_ping_rtt` per `(observer, peer)`
- support `--json`

- [ ] **Step 2: Compile-check Python**

Run:

```bash
python3 -m py_compile scripts/p2p/summarize_peer_scorecard.py
```

Expected: no output and exit code 0.

- [ ] **Step 3: Run against live logs**

Run:

```bash
scripts/p2p/summarize_peer_scorecard.py --tail-lines 12000 --limit 20
```

Expected: table rows with non-empty observer, peer, and score fields.

Commit:

```bash
git add scripts/p2p/summarize_peer_scorecard.py
git commit -m "Add advisory P2P peer scorecard"
```

## Task 5: Deployment Documentation

**Files:**
- Modify: `/private/tmp/bedrock-mainnet-deployment/runbooks/zcash-p2p-ingress.md`
- Modify: `/private/tmp/bedrock-mainnet-deployment/docs/current-state.md`
- Modify: `/private/tmp/bedrock-mainnet-deployment/docs/deployment-log.md`

- [ ] **Step 1: Update runbook**

Document this text:

````markdown
Useful peer portfolio commands:

```sh
scripts/p2p/summarize_crawler_events.py --tail-lines 5000
scripts/p2p/summarize_peer_scorecard.py --tail-lines 12000 --limit 20
```

The peer scorecard is advisory. It does not cause observers to disconnect or
prefer peers until a later rotation phase is explicitly enabled.
````

- [ ] **Step 2: Deploy timing build to observer hosts**

Use the existing source archive and remote install flow. Build on each Linux VM, restart `bedrock-p2p-ingress.service`, and keep crawler mode enabled.

- [ ] **Step 3: Verify fleet health**

Run:

```bash
scripts/health/check_bedrock_health.py
scripts/p2p/summarize_crawler_events.py --tail-lines 5000
scripts/p2p/summarize_peer_scorecard.py --tail-lines 12000 --limit 20
```

Expected:

- every observer has `bedrock-p2p-ingress=active`
- Asia observer has crawler events
- scorecard has peer rows
- no submitblock or FORGE forwarding is enabled

- [ ] **Step 4: Update docs with live evidence**

Add the fresh health and scorecard excerpts to `docs/current-state.md` and append a dated section to `docs/deployment-log.md`.

- [ ] **Step 5: Commit and push**

Run:

```bash
git add runbooks/zcash-p2p-ingress.md docs/current-state.md docs/deployment-log.md scripts/p2p/summarize_peer_scorecard.py
git commit -m "Document P2P peer scorecard telemetry"
git push
```

## Phase 1 Completion Criteria

- `cargo test -p bedrock-p2p-ingress` passes.
- Bedrock timing telemetry commit is pushed.
- Deployment scorecard script is committed and pushed.
- All deployed observer services remain active.
- Live scorecard output ranks peers by first/early block contribution.
- Runtime behavior remains measurement-only: no connection rotation, no P2P-to-FORGE forwarding, and no submitblock.
