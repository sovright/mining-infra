# Settlement API — Design

**Date:** 2026-06-23
**Branch:** `fix/durable-payout-state` (PR #56, sovright/mining-infra)
**Repos:** `bedrock` (pool) + `Bedrock-product/sovright-api` (payout engine)

## Problem

PR #56 made the pool's `PayoutTracker` durable on disk and added pruning
primitives (`mark_miner_settled` / `prune_settled_miners`). Those primitives
have **no production callers** and operate on an identity (IP address) that the
payout engine cannot name. Without a settlement mechanism the durable miners map
and its on-disk file grow unbounded with every distinct identity ever seen.

### Current state (verified)

- The pool records shares into `PayoutTracker`, keyed by **IP address**
  (`addr.ip().to_string()`, fallback `channel_<id>`) at
  `crates/zcash-pool-server/src/server.rs:1234`.
- The pool's per-worker metrics (`shares_accepted_total{worker="..."}`,
  `hashrate_sol_s{worker}`) come from a **separate** `worker_hashrate_tracker`
  keyed by **worker name**.
- `sovright-api` ingests only the per-**worker-name** counters from the pool's
  Prometheus endpoint (`src/ingest/metrics_parser.rs`, `src/ingest/poller.rs`),
  accumulates credit per worker in Postgres, maps workers → zcash addresses, and
  pays per address (FPPS).
- The pool has **no inbound control API** — only the outbound hyper 0.14
  `/metrics` server in `sovright-telemetry` (`src/metrics.rs`).
- Net: three identity spaces (pool durable tracker = IP; pool metrics = worker
  name; sovright-api = worker name → address). The durable tracker's totals are
  not consumed downstream and its identity is unnameable by the payer.

## Goals

1. One identity — **worker name** — across the pool durable tracker, the
   per-worker metrics, and sovright-api.
2. A pool **inbound control plane** so sovright-api can settle workers it has
   paid, bounding the durable map/file growth.
3. sovright-api drives settlement automatically after confirmed payouts, with an
   operator-visible status surface.

## Non-goals

- Replacing the metrics-polling ingest path (sovright-api keeps polling
  `/metrics` for share credit; the control API is for settlement only).
- Making the pool's durable totals authoritative for payout amounts — sovright-api's
  Postgres ledger remains authoritative.
- Per-share timestamping in the tracker.

## Decisions (from brainstorming)

1. **Both as one feature** — thin settle/prune control endpoint on the pool +
   operator-facing settlement workflow in sovright-api that calls it.
2. **Re-key the durable tracker to worker name** (fixes the IP-keying latent bug:
   NAT collapse / reconnect split).
3. **Control transport:** reuse hyper 0.14 (same stack as `/metrics`), a separate
   `control_addr` (default `127.0.0.1`), bearer-token auth with constant-time
   compare, `serde_json` bodies. No new HTTP framework dependency.
4. **Settle semantics:** explicit paid total from sovright-api. The pool sets the
   watermark to `min(settled_total_shares, current_total)`, monotonic (never moves
   backward), idempotent on retry. No over-settle.

## Architecture

The pool gains an inbound control plane; it previously had only outbound metrics.
`sovright-api` stays the authoritative ledger and becomes the driver: after it
pays a worker it calls `POST /v1/settle` with the cumulative shares paid through
and a settlement reference; the pool records a watermark and later prunes
fully-settled, idle workers, archiving each pruned record first.

```
miner --shares--> pool (PayoutTracker, keyed by worker name, durable)
                    |  outbound /metrics  (existing)
                    v
              sovright-api  --ingest--> Postgres ledger --FPPS--> ZEC payout
                    |                                                  |
                    |  POST /v1/settle {worker, settled_total_shares,  |
                    |       settlement_ref}  <-------------------------+
                    v  (after confirmed payout)
              pool control plane (hyper, bearer token) -> watermark
                    |
              maintenance loop -> prune_settled_miners(retention) -> JSONL archive
```

## Pool side — `zcash-pool-common` + `zcash-pool-server`

### P1. Re-key durable tracker to worker name

- Build `miner_id` from `resolve_worker_label(worker_identity, channel_id)`
  instead of `addr.ip()` (`server.rs:1234`). This unifies the durable tracker,
  the per-worker metrics, and sovright-api on worker name.
- **Unnamed workers** (the `channel_<id>` fallback when `worker_identity` is
  `None`) are NOT persisted or settle-eligible — they cannot be paid by name —
  and remain subject to normal idle eviction. Persistence/settlement applies only
  to named workers.
- **State migration:** bump `PAYOUT_STATE_VERSION` (1 → 2). Existing per-IP files
  fail the version check and are quarantined by the existing load logic (clean
  start). Acceptable: this is the first persistence release (pre-production).

### P2. `PayoutTracker` API changes (`payout.rs`)

- `mark_miner_settled(worker: &MinerId, settled_total_shares: u64, settlement_ref: S)`:
  - watermark `settled_total_shares = min(settled_total_shares, current total)`,
  - **monotonic**: never decreases an existing watermark,
  - sets `settled_at_unix_ms`, `settlement_ref`,
  - idempotent: repeating the same call is a no-op,
  - returns `Option<SettleOutcome { total_shares, settled_total_shares }>`
    (`None` if the worker is unknown),
  - marks the tracker dirty (durable on next flush).
- Prune eligibility (`archive_record_if_prunable`): gate on **share-count
  equality** (`settled_total_shares == total_shares`) + idle ≥ retention +
  `settled_at_unix_ms` aged ≥ retention. Drop the cross-system `f64`
  `settled_total_difficulty == total_difficulty` requirement from the gate;
  difficulty is still written to the archive record for audit.
- `prune_settled_miners(retention, archive_path)` is called from the server's 60s
  maintenance loop (in addition to the existing per-test calls).

### P3. Control server (new hyper 0.14 service)

- New service bound to `control_addr` (default `127.0.0.1:9091`), reusing the
  `sovright-telemetry` hyper pattern. Lives in `sovright-telemetry` alongside the
  metrics server, or a `control` module in `zcash-pool-server` — chosen during
  planning to keep `PayoutTracker` access clean.
- Auth: bearer token from config, **constant-time** comparison
  (`subtle`-style or manual `ct_eq` over bytes — no new dep if avoidable).
- Bodies: `serde_json` (workspace-ubiquitous, well-established).
- Endpoints:
  - `POST /v1/settle` body `{worker, settled_total_shares, settlement_ref}`
    → `200 {worker, total_shares, settled_total_shares}`; `400` malformed;
    `401` missing/bad token; `404` unknown worker.
  - `GET /v1/payouts` → array of
    `{worker, total_shares, total_difficulty, settled_total_shares,
    settlement_ref, last_share_unix_ms}` for reconciliation before/after settle.
- Binds localhost by default; documented requirement to keep on a trusted
  network.

### P4. Config (`config.rs`)

- `control_addr: Option<SocketAddr>`
- `control_auth_token: Option<String>`
- `payout_settlement_retention: Duration` (default 24h)
- `payout_archive_path: Option<PathBuf>` (default: alongside `payout_state_path`,
  e.g. `payout-archive.jsonl`)
- Validation: `control_addr` set ⇒ `control_auth_token` must be non-empty.

## sovright-api side — `Bedrock-product/sovright-api`

### S1. Pool control client (`src/pool_control.rs`)

- `reqwest` wrapper for `POST /v1/settle` and `GET /v1/payouts`, base URL + token
  from config. Idempotent retry with bounded backoff on transient (5xx/network)
  errors; surfaces `404`/`401` distinctly.

### S2. Settlement hook

- When a shielded payout batch is **confirmed**, for each worker covered by the
  batch call `/v1/settle` with the cumulative `shares_accepted` the payout paid
  through, `settlement_ref` = payout batch id / payout txid.
- Persist "settled through" per worker (a column on the worker/payout record) so
  retries and crashes are idempotent.
- Exact confirmation hook (`fpps.rs` / wallet sweep state machine /
  `shielded_payouts`) is located and wired during planning.

### S3. Operator surface

- Expose settlement status (last settled total, ref, last pruned/seen) via the
  existing admin API / dashboard.
- Optional admin "settle worker" manual trigger that calls the pool, for
  reconciliation.

### S4. Config

- `POOL_CONTROL_URL`, `POOL_CONTROL_TOKEN`.

## Testing

### Pool
- Re-keying: shares from the same worker name aggregate; distinct names stay
  separate; unnamed workers are not persisted.
- `mark_miner_settled`: clamp to current total; monotonic; idempotent; unknown
  worker → `None`.
- Prune: count-equality gate; **never removes unsettled credit** (property test);
  archive written before removal; re-check under write lock.
- Control server: `401` (missing/bad token), `200` (valid settle), `404`
  (unknown worker), `400` (malformed); JSON round-trip.
- Version bump: old per-IP file is quarantined, pool starts clean.

### sovright-api
- Control client against a mock pool (success, 401, 404, retry on 5xx).
- Payout → settle integration: confirmed batch triggers settle with the correct
  cumulative shares and ref.
- Idempotent retry: duplicate settle calls do not double-anything.

## Risks

- Version bump = clean start of durable totals (acceptable pre-production).
- Worker name is miner-supplied; cardinality already capped by the
  `accepted_worker_identities` set, which also bounds the durable map.
- Two hyper listeners on the pool (metrics + control) — minor operational
  surface; control defaults to localhost.
- Float difficulty is no longer part of the prune gate — intentional, to avoid a
  cross-system equality that would never converge; share count is the
  authoritative settlement unit.
