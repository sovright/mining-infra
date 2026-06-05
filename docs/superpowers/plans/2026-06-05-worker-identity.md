# Worker Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Miners and the V1 proxy declare a worker name on connect; the pool labels per-worker metrics with it; the portal API parser accepts those metric names — completing per-worker attribution end to end.

**Architecture:** New client→server message `SetWorkerIdentity` (0x24) in the binary mining protocol, sent once after the transport handshake. The pool session loop dispatches on frame type (today it assumes every client frame is a share) and forwards identity to the server task, which enforces immutability and a pool-wide cardinality cap, stores the name on the `Channel`, and uses it as the metrics label with a `channel_N` fallback.

**Tech Stack:** Rust workspace (tokio, byteorder codec, prometheus metrics). Separate 2-line-plus-tests parser change in the Sovright-Mining-Pool repo (sqlx/axum API).

**Spec:** `docs/superpowers/specs/2026-06-05-worker-identity-design.md` (same branch)

**Repos / branches:**
- `/tmp/mining-infra` on branch `spec/worker-identity` (Tasks 1-6; spec already on this branch; one PR)
- `/Users/zakimanian/code/zcash-work/Sovright-Mining-Pool` (Task 7; new branch `fix/parser-worker-metric-names`, separate PR)

**Verification commands (mining-infra):** `cargo test -p <crate>` per task; full `cargo test --workspace && cargo clippy --workspace --all-targets` in Task 6.

**Commit footer for all commits:** `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. No emojis.

---

### Task 1: Protocol message + codec (`crates/zcash-mining-protocol`)

**Files:**
- Modify: `crates/zcash-mining-protocol/src/messages.rs`
- Modify: `crates/zcash-mining-protocol/src/codec.rs`

- [ ] **Step 1: Write failing tests** (append to the existing `#[cfg(test)]` module in `codec.rs`; read its existing round-trip tests first and match style):

```rust
#[test]
fn set_worker_identity_round_trip() {
    let msg = SetWorkerIdentity { worker_name: "e2eclaude-1".to_string() };
    let encoded = encode_set_worker_identity(&msg).unwrap();
    let decoded = decode_set_worker_identity(&encoded).unwrap();
    assert_eq!(decoded.worker_name, "e2eclaude-1");
}

#[test]
fn set_worker_identity_frame_type_is_0x24() {
    let msg = SetWorkerIdentity { worker_name: "a".to_string() };
    let encoded = encode_set_worker_identity(&msg).unwrap();
    let frame = MessageFrame::decode(&encoded).unwrap();
    assert_eq!(frame.msg_type, message_types::SET_WORKER_IDENTITY);
}

#[test]
fn worker_name_validation() {
    assert!(validate_worker_name("rig-1").is_ok());
    assert!(validate_worker_name("addr.worker_2").is_ok());
    assert!(validate_worker_name("").is_err());
    assert!(validate_worker_name(&"x".repeat(65)).is_err());
    assert!(validate_worker_name(&"x".repeat(64)).is_ok());
    assert!(validate_worker_name("has space").is_err());
    assert!(validate_worker_name("emoji🔥").is_err());
    assert!(validate_worker_name("inject\"label").is_err());
}

#[test]
fn decode_rejects_invalid_names() {
    // Hand-build a frame whose payload contains a forbidden byte.
    let payload = [1u8, b' ']; // name_len=1, name=" "
    let frame = MessageFrame {
        extension_type: 0,
        msg_type: message_types::SET_WORKER_IDENTITY,
        length: payload.len() as u32,
    };
    let mut data = frame.encode().to_vec();
    data.extend_from_slice(&payload);
    assert!(decode_set_worker_identity(&data).is_err());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd /tmp/mining-infra && cargo test -p zcash-mining-protocol set_worker_identity worker_name_validation decode_rejects`
Expected: compile errors (`SetWorkerIdentity`, `validate_worker_name` not found).

- [ ] **Step 3: Implement**

In `messages.rs`, add to `message_types`:

```rust
    /// SetWorkerIdentity message type (client -> server, once per connection)
    pub const SET_WORKER_IDENTITY: u8 = 0x24;
```

and below the existing message structs (match the file's derive style — the existing structs derive `Debug, Clone`):

```rust
/// Declares the worker name for this connection. Sent by the client once,
/// immediately after the transport handshake, before any shares. The pool
/// treats it as immutable for the life of the connection.
#[derive(Debug, Clone, PartialEq)]
pub struct SetWorkerIdentity {
    /// 1-64 bytes, restricted to [A-Za-z0-9._-].
    pub worker_name: String,
}

/// Maximum worker name length in bytes.
pub const MAX_WORKER_NAME_LEN: usize = 64;

/// Validate a worker name: 1-64 bytes of [A-Za-z0-9._-].
///
/// Restricted because the name becomes a Prometheus label value, a database
/// key, and dashboard text downstream.
pub fn validate_worker_name(name: &str) -> core::result::Result<(), crate::error::ProtocolError> {
    if name.is_empty() || name.len() > MAX_WORKER_NAME_LEN {
        return Err(crate::error::ProtocolError::EncodingError(format!(
            "worker name must be 1-{MAX_WORKER_NAME_LEN} bytes"
        )));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(crate::error::ProtocolError::EncodingError(
            "worker name may only contain [A-Za-z0-9._-]".into(),
        ));
    }
    Ok(())
}
```

In `codec.rs`, mirror the existing encode/decode pairs (see `encode_set_target`/`decode_set_target` for the closest small-message example; reuse the same frame/length checks as `decode_new_equihash_job` lines 110-126):

```rust
/// Encode a SetWorkerIdentity message
pub fn encode_set_worker_identity(msg: &SetWorkerIdentity) -> Result<Vec<u8>> {
    validate_worker_name(&msg.worker_name)?;

    let mut payload = Vec::with_capacity(1 + msg.worker_name.len());
    payload.write_u8(msg.worker_name.len() as u8).unwrap();
    payload.write_all(msg.worker_name.as_bytes()).unwrap();

    let frame = MessageFrame {
        extension_type: 0,
        msg_type: message_types::SET_WORKER_IDENTITY,
        length: payload.len() as u32,
    };

    let mut result = frame.encode().to_vec();
    result.extend(payload);
    Ok(result)
}

/// Decode a SetWorkerIdentity message
pub fn decode_set_worker_identity(data: &[u8]) -> Result<SetWorkerIdentity> {
    let frame = MessageFrame::decode(data)?;
    if frame.msg_type != message_types::SET_WORKER_IDENTITY {
        return Err(ProtocolError::InvalidMessageType(frame.msg_type));
    }

    let total_len = MessageFrame::HEADER_SIZE + frame.length as usize;
    if data.len() < total_len {
        return Err(ProtocolError::MessageTooShort { expected: total_len, actual: data.len() });
    }
    if data.len() > total_len {
        return Err(ProtocolError::EncodingError("trailing bytes in message".into()));
    }

    let payload = &data[MessageFrame::HEADER_SIZE..total_len];
    let mut cursor = Cursor::new(payload);
    let name_len = cursor.read_u8().map_err(|_| ProtocolError::MessageTooShort { expected: 1, actual: 0 })? as usize;
    let mut name_bytes = vec![0u8; name_len];
    cursor
        .read_exact(&mut name_bytes)
        .map_err(|_| ProtocolError::MessageTooShort { expected: name_len, actual: payload.len().saturating_sub(1) })?;

    let worker_name = String::from_utf8(name_bytes)
        .map_err(|_| ProtocolError::EncodingError("worker name is not UTF-8".into()))?;
    validate_worker_name(&worker_name)?;

    Ok(SetWorkerIdentity { worker_name })
}
```

Update the `use crate::messages::{...}` import lists in `codec.rs` to include `SetWorkerIdentity` and `validate_worker_name`. Adapt error-variant names to what `error.rs` actually defines (read it first — if `EncodingError`/`MessageTooShort`/`InvalidMessageType` differ, match reality).

- [ ] **Step 4: Run tests**

Run: `cargo test -p zcash-mining-protocol`
Expected: all PASS including the 4 new tests.

- [ ] **Step 5: Commit**

```bash
git add crates/zcash-mining-protocol
git commit -m "feat(protocol): SetWorkerIdentity message (0x24) with name validation"
```

---

### Task 2: Pool session — frame dispatch + identity forwarding (`crates/zcash-pool-server`)

**Files:**
- Modify: `crates/zcash-pool-server/src/session.rs`

The session read loop currently routes every inbound frame through `decode_share_message` (session.rs:99), which errors on any non-share type and disconnects. Restructure to dispatch on `frame.msg_type`.

- [ ] **Step 1: Write failing test** (in `session.rs`'s test module if one exists, else create one; this tests the pure classification step):

```rust
#[test]
fn classify_inbound_frames() {
    use zcash_mining_protocol::codec::{encode_set_worker_identity, encode_submit_share};
    use zcash_mining_protocol::messages::{SetWorkerIdentity, SubmitEquihashShare};

    let ident = encode_set_worker_identity(&SetWorkerIdentity { worker_name: "rig-1".into() }).unwrap();
    assert!(matches!(classify_message(&ident), Ok(InboundMessage::Identity(m)) if m.worker_name == "rig-1"));

    let share = SubmitEquihashShare {
        channel_id: 7,
        sequence_number: 0,
        job_id: 1,
        nonce_2: vec![0; 28],
        time: 0,
        solution: [0u8; 1344],
    };
    let share_bytes = encode_submit_share(&share).unwrap();
    assert!(matches!(classify_message(&share_bytes), Ok(InboundMessage::Share(_))));

    // Unknown type still errors (and the caller still disconnects on it).
    let mut unknown = ident.clone();
    unknown[2] = 0x7f;
    assert!(classify_message(&unknown).is_err());
}
```

(Adjust the `SubmitEquihashShare` literal to the struct's actual fields — read `messages.rs`.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p zcash-pool-server classify_inbound`
Expected: compile error (`classify_message`, `InboundMessage` not found).

- [ ] **Step 3: Implement**

Add to `session.rs`:

```rust
/// A decoded inbound client message.
pub enum InboundMessage {
    Share(SubmitEquihashShare),
    Identity(zcash_mining_protocol::messages::SetWorkerIdentity),
}

/// Decode an inbound frame by type. Unknown types are an error; the session
/// disconnects on them, same as before SetWorkerIdentity existed.
pub fn classify_message(msg_data: &[u8]) -> Result<InboundMessage> {
    let frame = MessageFrame::decode(msg_data).map_err(PoolError::Protocol)?;
    match frame.msg_type {
        message_types::SUBMIT_EQUIHASH_SHARE => {
            Ok(InboundMessage::Share(decode_submit_share(msg_data)?))
        }
        message_types::SET_WORKER_IDENTITY => Ok(InboundMessage::Identity(
            zcash_mining_protocol::codec::decode_set_worker_identity(msg_data)
                .map_err(PoolError::Protocol)?,
        )),
        other => Err(PoolError::InvalidMessage(format!(
            "Unknown message type: 0x{other:02x}"
        ))),
    }
}
```

Rework the read branch of `Session::run` (currently `match self.decode_share_message(&msg)` at line 99):

```rust
match classify_message(&msg) {
    Ok(InboundMessage::Share(share)) => {
        // keep the existing channel_id check from decode_share_message:
        if share.channel_id != self.channel_id {
            error!(
                "Share channel_id {} does not match session {} - disconnecting",
                share.channel_id, channel_id
            );
            break;
        }
        // ...existing handle_share(share) call and error handling unchanged...
    }
    Ok(InboundMessage::Identity(ident)) => {
        // Identity is informational: decode/validation errors never reach
        // here (classify_message returns Err), and policy (immutability,
        // cap) is enforced by the server task which owns channel state.
        if let Err(e) = self
            .server_tx
            .send(SessionMessage::IdentityDeclared {
                channel_id,
                worker_name: ident.worker_name,
            })
            .await
        {
            error!("Failed to forward identity for channel {}: {}", channel_id, e);
            break;
        }
    }
    Err(e) => {
        error!("Parse error for channel {}: {}", channel_id, e);
        break;
    }
}
```

Move the `share.channel_id != self.channel_id` check out of `decode_share_message` as shown (then delete `decode_share_message`, folding its share-decode into `classify_message`). Add the new variant to `SessionMessage`:

```rust
    /// Miner declared its worker identity (validated at decode; policy is
    /// enforced by the server, which owns channel state).
    IdentityDeclared { channel_id: u32, worker_name: String },
```

NOTE: a decode failure of a malformed 0x24 frame currently lands in the `Err` arm and disconnects. The spec says invalid identity should be ignored with a warning, keeping the connection. Distinguish: in `classify_message`, on a SET_WORKER_IDENTITY frame that fails `decode_set_worker_identity`, return a third variant instead of Err:

```rust
    InvalidIdentity(String), // reason; session warns and continues
```

with the session arm:

```rust
    Ok(InboundMessage::InvalidIdentity(reason)) => {
        warn!("Ignoring invalid worker identity on channel {}: {}", channel_id, reason);
    }
```

and a test case in `classify_inbound_frames` asserting a malformed 0x24 frame yields `InvalidIdentity`, not `Err`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p zcash-pool-server`
Expected: all PASS. The server won't compile until the new `SessionMessage` variant is handled — if `handle_session_message` has a non-exhaustive match error, add a temporary arm `SessionMessage::IdentityDeclared { .. } => Ok(())` (Task 3 replaces it).

- [ ] **Step 5: Commit**

```bash
git add crates/zcash-pool-server
git commit -m "feat(pool): dispatch inbound frames by type, forward worker identity"
```

---

### Task 3: Pool server — identity storage, cap, metric labels (`crates/zcash-pool-server`)

**Files:**
- Modify: `crates/zcash-pool-server/src/channel.rs` (field)
- Modify: `crates/zcash-pool-server/src/server.rs` (handling + labels)

- [ ] **Step 1: Add the field**

`Channel` (channel.rs:22) gains:

```rust
    /// Worker identity declared via SetWorkerIdentity (immutable once set).
    pub worker_identity: Option<String>,
```

Initialize to `None` in the constructor (find `Channel::new` / the struct literal that builds channels).

- [ ] **Step 2: Write failing tests** (server.rs test module; these test the pure policy function):

```rust
#[test]
fn identity_policy() {
    let mut accepted = std::collections::HashSet::new();

    // First identity accepted
    assert_eq!(
        apply_identity_policy(&mut accepted, &None, "rig-1", 2),
        IdentityDecision::Accept
    );
    accepted.insert("rig-1".to_string());

    // Immutable: second declaration on same channel ignored
    assert_eq!(
        apply_identity_policy(&mut accepted, &Some("rig-1".into()), "rig-2", 2),
        IdentityDecision::AlreadySet
    );

    // Same name on another channel is fine (doesn't grow the set)
    assert_eq!(
        apply_identity_policy(&mut accepted, &None, "rig-1", 2),
        IdentityDecision::Accept
    );

    // Cap reached for a NEW name
    accepted.insert("rig-9".to_string());
    assert_eq!(
        apply_identity_policy(&mut accepted, &None, "rig-3", 2),
        IdentityDecision::CapReached
    );
}

#[test]
fn worker_label_resolution() {
    assert_eq!(resolve_worker_label(&Some("rig-1".into()), 5), "rig-1");
    assert_eq!(resolve_worker_label(&None, 5), "channel_5");
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p zcash-pool-server identity_policy worker_label`
Expected: compile errors.

- [ ] **Step 4: Implement**

In `server.rs`:

```rust
/// Cap on distinct accepted worker identities per process. Identities are
/// attacker-controlled Prometheus label values; both the label and this set
/// live until process restart, so the cap bounds metric cardinality against
/// a client cycling names across reconnects.
const MAX_WORKER_IDENTITIES: usize = 10_000;

#[derive(Debug, PartialEq)]
enum IdentityDecision {
    Accept,
    AlreadySet,
    CapReached,
}

/// Pure policy: immutability first, then the cardinality cap (existing names
/// don't count against it).
fn apply_identity_policy(
    accepted: &mut std::collections::HashSet<String>,
    current: &Option<String>,
    name: &str,
    cap: usize,
) -> IdentityDecision {
    if current.is_some() {
        return IdentityDecision::AlreadySet;
    }
    if !accepted.contains(name) && accepted.len() >= cap {
        return IdentityDecision::CapReached;
    }
    IdentityDecision::Accept
}

/// Metrics label for a channel: declared identity, or `channel_N`.
fn resolve_worker_label(worker_identity: &Option<String>, channel_id: u32) -> String {
    worker_identity
        .clone()
        .unwrap_or_else(|| format!("channel_{channel_id}"))
}
```

Server state: add `accepted_identities` next to the existing shared channel map, using the same synchronization pattern the channel map uses (read `server.rs` around the `channels` field — if channels are `RwLock<HashMap<u32, Channel>>` on the server struct, add `accepted_identities: RwLock<HashSet<String>>`; if a different pattern, mirror it). All identity handling happens in the server task via `handle_session_message`, so contention is minimal.

Replace the temporary `IdentityDeclared` arm in `handle_session_message`:

```rust
SessionMessage::IdentityDeclared { channel_id, worker_name } => {
    let mut accepted = self.accepted_identities.write().await; // match the channel map's lock flavor
    let mut channels = self.channels.write().await;            // adapt to actual field/lock
    let Some(channel) = channels.get_mut(&channel_id) else {
        warn!("Identity for unknown channel {}", channel_id);
        return Ok(());
    };
    match apply_identity_policy(&mut accepted, &channel.worker_identity, &worker_name, MAX_WORKER_IDENTITIES) {
        IdentityDecision::Accept => {
            accepted.insert(worker_name.clone());
            info!("Channel {} identified as worker '{}'", channel_id, worker_name);
            channel.worker_identity = Some(worker_name);
        }
        IdentityDecision::AlreadySet => {
            warn!(
                "Channel {} attempted to re-declare identity '{}' (already '{}') - ignored",
                channel_id, worker_name,
                channel.worker_identity.as_deref().unwrap_or("?")
            );
        }
        IdentityDecision::CapReached => {
            warn!(
                "Worker identity cap ({}) reached; channel {} stays as channel_{}",
                MAX_WORKER_IDENTITIES, channel_id, channel_id
            );
        }
    }
    Ok(())
}
```

Metric labels: at the three `worker_label = format!("channel_{}", channel_id)` sites (server.rs ~1116, ~1184), the surrounding code in `handle_share_submission` already has channel access (it calls `channel.record_share()`); capture the label once where the channel is borrowed:

```rust
let worker_label = resolve_worker_label(&channel.worker_identity, channel_id);
```

and use it at all three call sites (stale-reject, accepted, rejected paths). Read the lock scopes carefully — if the channel borrow ends before the metric call, clone the label out of the lock scope (it's a String; cheap).

Do NOT add per-worker hashrate export: the pool has no per-channel hashrate estimator and the spec forbids building one for this feature.

- [ ] **Step 5: Run tests**

Run: `cargo test -p zcash-pool-server`
Expected: all PASS including the 2 new tests.

- [ ] **Step 6: Commit**

```bash
git add crates/zcash-pool-server
git commit -m "feat(pool): store worker identity with cardinality cap, label metrics by it"
```

---

### Task 4: Test miner sends identity (`crates/zcash-test-miner`)

**Files:**
- Modify: `crates/zcash-test-miner/src/worker.rs`

- [ ] **Step 1: Implement** (no isolated unit seam worth building here — the change is two statements on a live transport; E2E covers it)

In `run_worker_session`, immediately after the `info!(... "Connected to pool")` line that follows `MinerTransport::connect`:

```rust
    // Declare our worker identity so the pool can attribute shares to a
    // human-meaningful name instead of channel_N.
    let identity = zcash_mining_protocol::messages::SetWorkerIdentity {
        worker_name: config.worker_name.clone(),
    };
    let encoded = zcash_mining_protocol::codec::encode_set_worker_identity(&identity)?;
    transport.write_message(&encoded).await?;
    info!(worker = %config.worker_name, "Sent worker identity");
```

A failure propagates as a session error → existing reconnect loop retries (and re-sends, since this runs per session). Note: `config.worker_name` is `{prefix}-{i}` from `main.rs`, which always satisfies the validator if the prefix does; an invalid `--worker-prefix` (e.g. with spaces) will error every session — that is acceptable and visible (`Session error` log each retry). Optionally validate the prefix once in `main.rs` before spawning workers and exit with a clear message; do this if it is a <10-line change.

- [ ] **Step 2: Verify**

Run: `cargo test -p zcash-test-miner && cargo clippy -p zcash-test-miner`
Expected: existing tests PASS, clippy clean.

- [ ] **Step 3: Commit**

```bash
git add crates/zcash-test-miner
git commit -m "feat(test-miner): send SetWorkerIdentity after connect"
```

---

### Task 5: V1 proxy forwards SV1 username (`crates/sovright-v1-stratum-proxy`)

**Files:**
- Modify: `crates/sovright-v1-stratum-proxy/src/session.rs`

- [ ] **Step 1: Write failing sanitizer tests** (proxy session.rs test module, matching its existing test style):

```rust
#[test]
fn sanitize_worker_name_cases() {
    assert_eq!(sanitize_worker_name("rig-1"), Some("rig-1".to_string()));
    assert_eq!(sanitize_worker_name("addr.worker"), Some("addr.worker".to_string()));
    assert_eq!(sanitize_worker_name("has space!"), Some("has_space_".to_string()));
    assert_eq!(sanitize_worker_name(&"x".repeat(80)), Some("x".repeat(64)));
    assert_eq!(sanitize_worker_name(""), None);
    assert_eq!(sanitize_worker_name("🔥🔥"), Some("__".to_string()));
}
```

(Decide the all-invalid case deliberately: replacing yields `"__"` which is valid; only the empty string yields `None`. The test above pins that.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p sovright-v1-stratum-proxy sanitize_worker`
Expected: compile error.

- [ ] **Step 3: Implement**

```rust
/// Sanitize an SV1 username into a protocol-valid worker name: replace any
/// byte outside [A-Za-z0-9._-] with '_', truncate to 64 bytes. Returns None
/// for an empty input (caller skips identity; pool falls back to channel_N).
/// Sanitize rather than reject: SV1 usernames are arbitrary ASIC-config
/// strings and the proxy must not refuse service over a label.
fn sanitize_worker_name(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    let cleaned: String = raw
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' {
                b as char
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    Some(cleaned)
}
```

In `connect_upstream` (session.rs:624), immediately after `self.upstream = Some(upstream);`, send the identity (covers first connect AND reconnects, since reconnects go through this fn):

```rust
        // Forward the SV1 username as our upstream worker identity so the
        // pool attributes this connection's shares to it.
        if let Some(name) = self.worker_name.as_deref().and_then(sanitize_worker_name) {
            let msg = zcash_mining_protocol::messages::SetWorkerIdentity { worker_name: name };
            match zcash_mining_protocol::codec::encode_set_worker_identity(&msg) {
                Ok(encoded) => {
                    let Some(upstream) = self.upstream.as_mut() else {
                        return Err(SessionError::UpstreamClosed);
                    };
                    upstream.write_raw(&encoded).await?;
                }
                Err(e) => {
                    // Can't happen post-sanitization; never block mining on a label.
                    warn!(error = %e, "Failed to encode worker identity, continuing anonymous");
                }
            }
        }
```

`write_raw`: read how `UpstreamConnection::write_share` (used at session.rs:540) writes to the stream and add a sibling method that writes pre-encoded bytes the same way (same framing — `write_share` likely encodes then writes; factor or duplicate the raw-write portion). Fix the borrow order if `self.upstream.as_mut()` conflicts with the surrounding code — the snippet runs right after `self.upstream = Some(...)`, so restructure to use that binding directly if cleaner.

Timing note: today the proxy connects upstream lazily; verify whether `connect_upstream` can run BEFORE `mining.authorize` sets `worker_name` (e.g. on subscribe). If it can, also send the identity at the end of `handle_authorize` when an upstream connection already exists — same snippet factored into a `send_worker_identity(&mut self)` helper called from both places. The immutability rule means only the first one the pool sees wins; sending twice with the same name is harmless (second is warned + ignored).

- [ ] **Step 4: Run tests**

Run: `cargo test -p sovright-v1-stratum-proxy && cargo clippy -p sovright-v1-stratum-proxy`
Expected: PASS, clean.

- [ ] **Step 5: Commit**

```bash
git add crates/sovright-v1-stratum-proxy
git commit -m "feat(v1-proxy): forward sanitized SV1 username as worker identity"
```

---

### Task 6: Workspace verification + PR (mining-infra)

- [ ] **Step 1:** `cd /tmp/mining-infra && cargo test --workspace && cargo clippy --workspace --all-targets`
Expected: all green, no new warnings.

- [ ] **Step 2:** Push and open the PR:

```bash
git push -u origin spec/worker-identity
gh pr create --base main --title "feat: worker identity on the mining protocol" \
  --body "<summarize: spec + SetWorkerIdentity (0x24), pool dispatch/labeling with cardinality cap, test-miner + v1-proxy senders; link spec file; note the API parser companion PR in Sovright-Mining-Pool>"
```

---

### Task 7: API parser accepts per-worker metric names (Sovright-Mining-Pool repo)

**Files:**
- Modify: `/Users/zakimanian/code/zcash-work/Sovright-Mining-Pool/sovright-api/src/ingest/metrics_parser.rs`
- Branch: `fix/parser-worker-metric-names` off current `main`

- [ ] **Step 1: Write failing test** (existing test module in `metrics_parser.rs`; follow its `parse + extract` test style, e.g. `test_extract_worker_hashrates` at ~line 263):

```rust
#[test]
fn test_extract_share_counters_worker_prefixed_names() {
    let input = r#"
worker_shares_accepted_total{worker="rig-1"} 42
worker_shares_rejected_total{worker="rig-1"} 3
worker_blocks_found_total{worker="rig-1"} 1
"#;
    let metrics = parse_prometheus_text(input); // match the actual parse entry point used by sibling tests
    let counters = extract_share_counters(&metrics);
    let c = counters.get("rig-1").expect("rig-1 present");
    assert_eq!(c.accepted, 42);
    assert_eq!(c.rejected, 3);
    assert_eq!(c.blocks_found, 1);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd sovright-api && cargo test -p sovright-api worker_prefixed_names`
Expected: FAIL (counters empty — names not matched).

- [ ] **Step 3: Implement** — extend the three match arms in `extract_share_counters` (~line 148):

```rust
"shares_accepted_total" | "stratum_shares_accepted_total" | "worker_shares_accepted_total" => { ... }
"shares_rejected_total" | "stratum_shares_rejected_total" | "worker_shares_rejected_total" => { ... }
"blocks_found_total" | "stratum_blocks_found_total" | "worker_blocks_found_total" => { ... }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p sovright-api && cargo clippy --all-targets`
Expected: PASS, clean.

- [ ] **Step 5: Commit + PR**

```bash
git add sovright-api/src/ingest/metrics_parser.rs
git commit -m "fix(ingest): accept worker_-prefixed per-worker metric names from the pool"
git push -u origin fix/parser-worker-metric-names
gh pr create --base main --title "fix(ingest): accept worker_-prefixed per-worker metric names" --body "<link mining-infra worker-identity PR; explain attribution chain>"
```

---

## Post-merge (manual, not part of this plan)

1. Deploy: rebuild pool + proxy + test-miner binaries on the testnet VM (pool no later than clients); merge the parser PR (auto-deploys via Cloud Build).
2. E2E: `zcash-test-miner --pool-addr stratum.sovright.com:3333 --worker-prefix <name> --solver-threads 1`; verify `worker_shares_accepted_total{worker="<name>-0"}` in pool metrics, the unclaimed row via `GET /api/workers/unclaimed?prefix=<name>`, claim through onboarding, and dashboard attribution. Repeat via the SV1 proxy with a stratum username.
