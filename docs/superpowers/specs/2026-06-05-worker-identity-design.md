# Worker Identity on the Mining Protocol

**Date:** 2026-06-05
**Status:** Approved design
**Repos:** sovright/mining-infra (protocol, pool, test miner, V1 proxy), sovright/Sovright-Mining-Pool (API metrics parser — separate small PR)

## Problem

The custom mining protocol (`zcash-mining-protocol`) has no worker-identity message. Its
complete message set is `NewEquihashJob` (0x20), `SubmitEquihashShare` (0x21),
`SubmitSharesResponse` (0x22), and `SetTarget` (0x23). Consequences:

- The pool cannot know who is mining on a connection. Per-worker metrics are labeled
  `channel_N` (`zcash-pool-server/src/server.rs`, `worker_label = format!("channel_{}", channel_id)`),
  which is meaningless to users and unstable across reconnects.
- The test miner's `--worker-prefix` is used only in its own log lines; it is never
  transmitted.
- The V1 stratum proxy captures the SV1 username from `mining.authorize`
  (`MinerSession.worker_name`) but has no way to forward it upstream, so ASIC
  attribution is equally broken.
- Downstream, the `sovright-api` ingest poller resolves workers by the metrics `worker`
  label. With `channel_N` labels, per-worker dashboards, hashrate charts, FPPS
  crediting, and the anonymous-mine-then-claim flow
  (`unclaimed_workers`, spec `2026-06-04-cpu-first-onboarding-flow-design.md` in
  Sovright-Mining-Pool) cannot work.

Additionally, the API's parser only accepts `shares_accepted_total` /
`stratum_shares_accepted_total` metric names, while the pool exports
`worker_shares_accepted_total` — so even the channel-labeled counters are ignored today.

## Goals

1. A miner (or proxy, on behalf of a downstream miner) can declare a worker name for its
   connection.
2. The pool labels per-worker metrics with that name, falling back to `channel_N` when
   absent.
3. The test miner and the V1 proxy both send identity, covering the CPU quickstart and
   ASIC paths.
4. The `sovright-api` parser accepts the pool's per-worker metric names, completing the
   attribution chain end to end.

## Non-goals

- Authentication. Identity is a self-declared label on a valueless testnet; first-come
  claim semantics live in the portal API, not the protocol.
- Mutable / re-assignable identity on a live connection (decision: immutable; see below).
- SV2-spec (Stratum V2 standard) interop — this is the project's own protocol.
- Payout-address-based identity.

## Decisions

| Decision | Choice |
|---|---|
| Mechanism | New message `SetWorkerIdentity` (0x24), client→server, after noise handshake |
| Lifecycle | Immutable per connection: first valid message wins, later ones ignored + warned |
| Pre-identity shares | Attributed to the fallback `channel_N` label |
| Charset / length | 1–64 bytes, `[A-Za-z0-9._-]` only |
| Cardinality | Pool-wide cap on distinct accepted identities (const, 10_000); beyond it, fall back to `channel_N` |
| Rejected alternatives | Field on `SubmitEquihashShare` (breaks fixed-layout decoding on the hot path); identity in noise handshake payload (couples cosmetic feature to security-critical code) |

## Design

### 1. Protocol (`crates/zcash-mining-protocol`)

```rust
// messages.rs
pub mod message_types {
    // ...existing 0x20-0x23...
    /// SetWorkerIdentity message type (client -> server, once per connection)
    pub const SET_WORKER_IDENTITY: u8 = 0x24;
}

/// Declares the worker name for this connection. Sent by the client once,
/// immediately after the transport handshake, before any shares.
pub struct SetWorkerIdentity {
    /// 1-64 bytes, restricted to [A-Za-z0-9._-].
    pub worker_name: String,
}
```

Wire format (frame payload): `name_len: u8` followed by `name_len` bytes. The codec gains
`encode_set_worker_identity` / `decode_set_worker_identity` mirroring the existing
encode/decode pairs, plus a shared validator:

```rust
/// Validate a worker name: 1-64 bytes of [A-Za-z0-9._-].
pub fn validate_worker_name(name: &str) -> Result<(), ProtocolError>;
```

The charset is restricted because the name becomes a Prometheus label value, a database
key (`unclaimed_workers.stratum_auth` in the portal), and user-visible dashboard text.
`[A-Za-z0-9._-]` is safe in all three and covers both naming conventions already in the
field (`prefix-N` from the CPU miner, `address.worker` from ASIC configs — note `.` is
allowed). Validation is enforced at encode (client refuses to send garbage) and decode
(server refuses to accept it).

### 2. Pool (`crates/zcash-pool-server`)

- Channel state gains `worker_identity: Option<String>`.
- **Dispatch restructure required:** the pool's read loop currently assumes every
  client frame is a share (`decode_share_message` or error→disconnect). It must branch
  on `frame.msg_type` first and route 0x21 vs 0x24, keeping the
  unknown-type→disconnect behavior for everything else.
- The pool-wide identity cap is shared state across per-session tasks; it lives
  alongside the existing shared channel map (same `RwLock`/server-state pattern), as a
  `HashSet<String>` of accepted identities. The plan must pin its locking placement.
- New handling for `SET_WORKER_IDENTITY` frames:
  - decode + validate; on decode/validation failure: `warn!`, ignore, keep connection.
  - if identity already set for the channel: `warn!`, ignore (immutability).
  - if the pool-wide distinct-identity count is at the cap (`MAX_WORKER_IDENTITIES:
    usize = 10_000`): `warn!`, ignore (channel falls back to `channel_N`). This bounds
    Prometheus label cardinality against a hostile client cycling names across
    reconnects. The count tracks distinct accepted identity strings for the process
    lifetime (matching Prometheus label lifetime, which also lives until restart).
  - otherwise store it and `info!` the association.
- Label resolution at all per-worker metric call sites (accepted/rejected/block-found,
  currently three sites in `server.rs`, plus per-worker hashrate if/where
  `set_worker_hashrate` is called):

```rust
let worker_label = channel
    .worker_identity
    .clone()
    .unwrap_or_else(|| format!("channel_{channel_id}"));
```

- Per-worker hashrate: wherever the pool computes per-channel hashrate, export it via
  `set_worker_hashrate(&worker_label, value)` with the same resolution, so
  `hashrate_sol_s{worker="..."}` carries real names. (The API already parses that series
  name.) If the pool does not currently compute per-channel hashrate, exporting the
  share counters alone is sufficient for attribution and crediting — hashrate then
  derives from share difficulty in the API; do not build a new hashrate estimator for
  this feature.

### 3. Test miner (`crates/zcash-test-miner`)

In `run_worker_session`, immediately after `MinerTransport::connect` succeeds, encode and
send `SetWorkerIdentity { worker_name: config.worker_name.clone() }` (the existing
`{prefix}-{i}` value). A send failure is treated like any other transport error (session
error → reconnect). No CLI changes. The reconnect loop naturally re-sends on each new
session.

### 4. V1 proxy (`crates/sovright-v1-stratum-proxy`)

`MinerSession` already holds `worker_name: Option<String>` (set by `mining.authorize`)
and connects upstream afterwards. Immediately after the upstream connection is
established (including reconnects), if `worker_name` is set, sanitize and send:

- Sanitization: replace any character outside `[A-Za-z0-9._-]` with `_`, then truncate
  to 64 bytes; if the result is empty, skip sending (fall back to `channel_N`).
  Sanitization (not rejection) because SV1 usernames are arbitrary ASIC-config strings
  and the proxy should not refuse service over a label.
- Identity is per upstream connection and the proxy holds one upstream connection per
  downstream miner, so multiplexing is not a concern.

### 5. API parser (`sovright/Sovright-Mining-Pool`, separate PR)

`extract_share_counters` in `sovright-api/src/ingest/metrics_parser.rs` additionally
matches the pool's exported names:

```rust
"shares_accepted_total" | "stratum_shares_accepted_total" | "worker_shares_accepted_total" => ...
"shares_rejected_total" | "stratum_shares_rejected_total" | "worker_shares_rejected_total" => ...
"blocks_found_total"    | "stratum_blocks_found_total"    | "worker_blocks_found_total"    => ...
```

`extract_worker_hashrates` already matches `hashrate_sol_s` — no change. With real
worker names in the labels, the existing ingest → `unclaimed_workers` → claim →
attribution chain works without further changes.

## Compatibility & rollout

There are no third-party clients of this protocol: the test miner and the V1 proxy are
the only implementations, and we deploy them alongside the pool. No compatibility
machinery is needed.

- The `channel_N` fallback exists for robustness (shares arriving before the identity
  message, identity rejected by validation/cap), not for legacy clients.
- For the record: the pre-change pool disconnects on unknown frame types, so the pool
  binary should be updated no later than the clients on the testnet VM. In practice all
  three ship in one deploy.
- The API parser PR is safe in any order — it only adds accepted metric names.

## Error handling summary

| Condition | Behavior |
|---|---|
| Invalid name (charset/length) at encode | Client-side error; nothing sent |
| Invalid name at decode | Pool warns, ignores, connection stays up |
| Duplicate identity message | Pool warns, ignores (first one wins) |
| Identity cap reached | Pool warns, channel uses `channel_N` |
| Identity never sent | `channel_N` label (status quo) |
| Proxy username sanitizes to empty | Proxy skips sending |

## Testing

- **Protocol:** codec round-trip; decode rejects empty, >64, bad charset; frame type
  registered; TDD.
- **Pool:** label resolution unit tests — identity set / unset / duplicate / invalid /
  cap reached; metric export includes the identity label.
- **Test miner:** session sends identity first (transport-level unit test or message
  ordering assertion where the test harness allows).
- **Proxy:** sanitization table test (passthrough, replacement, truncation, empty);
  re-send on upstream reconnect.
- **API parser:** name-acceptance tests for the three `worker_*` series.
- **E2E (manual, post-deploy):** run `zcash-test-miner --worker-prefix <name>` against the
  testnet pool; verify `worker_shares_accepted_total{worker="<name>-0"}` in pool
  metrics, an `unclaimed_workers` row in the portal DB, and a successful claim through
  onboarding. Repeat via the SV1 proxy path with a stratum username.
