# Miner-Direct Block Injection

**Status:** Design + Phase-3 PoC (miner-side client scaffolded, relay-side endpoint stubbed)
**Author:** R&D
**Related crates:** `sovright-relay`, `sovright-relay-sidecar`, `sovright-p2p-ingress`,
`zcash-equihash-validator`, `sovright-miner-injector` (new, PoC)

## 1. Motivation

Today a freshly-found block reaches the relay mesh only after it has propagated
through native Zcash P2P gossip and been picked up by `sovright-p2p-ingress`. The
relay mesh then FEC-floods it inter-region so every region's Zebra can
`submitblock` it. Because we are downstream of gossip, we win the first-to-Zebra
race in only ~8% of blocks — a listener-relay can arbitrate geography but cannot
beat the block's own origin.

**The structural lever:** let the miner/pool that *found* the block hand it
directly to its nearest relay, which floods it across the mesh *before* gossip
even starts. This turns the relay mesh into the fastest path from miner to every
region's Zebra.

```
                         ┌──────── today ────────┐
  miner ──> local zebrad ──> P2P gossip ──> p2p-ingress ──> relay mesh ──> all-region Zebra
                                                                (we start here, ~8% wins)

                         ┌──── this proposal ────┐
  miner ──> nearest relay injection endpoint ──> relay mesh ──> all-region Zebra
             (PoW-validate, then flood)             (we start at t=0)
```

## 2. How a block enters and floods today (the seam we hook into)

Investigated in `sovright-relay`, `sovright-relay-sidecar`, `sovright-p2p-ingress`.

### 2.1 The gossip-ingress injection path (the model to mirror)

`sovright-p2p-ingress` acquires a full serialized block over P2P and injects it
into the mesh through a single method:

- **`RelayBridge::forward_block(&self, block_payload: &[u8], tx_cache: Option<&TxCache>) -> Result<ForwardedBlock>`**
  — `crates/sovright-p2p-ingress/src/relay_bridge.rs:163`

  It (a) builds a `CompactBlock` from the raw bytes
  (`compact_block_from_raw_block*`, `block.rs:22-26`); (b) runs **first-seen-wins
  dedup** against a time-windowed LRU ring (`relay_bridge.rs:185-200`), returning
  `ForwardMode::Deduplicated` on a repeat; (c) broadcasts via the relay client
  handle; (d) records the hash only on success (`relay_bridge.rs:246`).

- The actual broadcast primitive is the cloneable **`BlockSender`**
  (`crates/sovright-relay/src/relay/client.rs:39`), obtained from
  `RelayClient::sender()` (`client.rs:168`):
  - `BlockSender::send(CompactBlock)` — `client.rs:45` (compact path,
    called at `relay_bridge.rs:217`)
  - `BlockSender::send_raw_block_segment(RawBlockSegment)` — `client.rs:53`
    (raw-segment path for oversized blocks, `relay_bridge.rs:331`)

  Both just enqueue a `RelayPayload` onto an mpsc channel drained by
  `RelayClient::run_with_outgoing` (`client.rs:213`).

### 2.2 What the client does with an enqueued block (the flood)

`RelayClient` drains the channel and, per payload
(`send_payload_internal`, `client.rs:311`):

- **Compact block:** `chunker.compact_block_to_chunks()`
  (`transport/chunker.rs:296`) → FEC-encode → HMAC-auth each chunk → UDP fan-out
  to every relay peer (`send_chunks_internal`, `client.rs:350`).
- **Raw block:** the full serialized block is first cut into segments by
  **`split_raw_block(block_hash, raw_block, max_frame_len) -> Vec<RawBlockSegment>`**
  (`segmented_block.rs:173`); each segment is an independent relay object
  (`raw_block_segment_to_chunks`, `chunker.rs:306`) → FEC → HMAC → UDP fan-out.

FEC: Reed–Solomon `data_shards + parity_shards` (`fec/encoder.rs:49`). Default
10+3; the **production raw-segment budget is 224+32** (max total shards 256),
configured via `SOVRIGHT_RELAY_DATA_SHARDS` / `_PARITY_SHARDS`.

### 2.3 The mesh transport and its auth

- UDP datagram transport, no handshake. Every chunk is authenticated per-packet
  with **HMAC-SHA256 keyed on a pre-shared 32-byte `auth_key`**
  (`transport/session.rs:119,153-187`), constant-time verified
  (`subtle::ConstantTimeEq`). Replay defense: per-`(block_hash, chunk_id)` seen-set,
  120 s TTL (`session.rs:190`).
- A relay node only accepts chunks whose key is in `authorized_keys`
  (`RelayNode::is_authorized`, `relay/node.rs:137`).

### 2.4 The relay node re-floods **only PoW-valid** chunks

Critically, the relay **node** never accepts a whole block — it re-floods
chunk-by-chunk, and gates on PoW first:

- `process_chunk_for_session` (`node.rs:551`) adds a chunk to its assembly, then
  **eagerly validates PoW** via `validate_pow_from_assembly` (`node.rs:590`) as
  soon as enough of the header is present; only assemblies with
  `pow_validated == true` emit chunks to `forward_to_peers` (`node.rs:413-440,
  443`). The validator is the pluggable `PowValidator` trait
  (`transport/pow.rs:24`); production uses `EquihashPowValidator`
  (`transport/pow.rs`), which runs `equihash::is_valid_solution(200, 9, …)` over
  the reconstructed header.

**Implication:** the mesh already refuses to propagate junk that fails Equihash.
Miner injection does not weaken this — but it should *also* validate up front (see
§5) so a bad block is rejected before it consumes even the first hop's bandwidth.

### 2.5 The sidecar submit path (unchanged by this work)

`sovright-relay-sidecar` receives reassembled blocks off the mesh
(`spawn_relay_block_handler`, `main.rs:465`; `handle_relay_raw_block`,
`submit.rs:439`) and calls Zebra `submitblock` (`rpc.rs:153`) behind an optional
cheap `SubmitGate` (parent-known / height-window / hash-dedup;
`submit_gate.rs:155`). Miner-injected blocks arrive here identically to
gossip-sourced ones — no sidecar change required.

### 2.6 The injection seam (where miner blocks enter)

> **Seam:** `RelayBridge::forward_block` (`relay_bridge.rs:163`), backed by
> `BlockSender::send` / `send_raw_block_segment` (`client.rs:45,53`) and, for raw
> blocks, `split_raw_block` (`segmented_block.rs:173`).

A miner-injected block is *the same kind of object* as a gossip-sourced block: a
full serialized Zcash block (`&[u8]`). So the injection endpoint's job is simply
to authenticate + PoW-validate the miner's bytes and then call the exact same
seam. Both paths feed one mesh; shared dedup prevents double-flood (§8).

## 3. Protocol: the miner front door

Miners should **not** speak the raw UDP mesh protocol. Reasons:

- The mesh uses a *shared* 32-byte PSK for all peers; handing that to every pool
  would let any pool impersonate any relay peer and inject at will, fleet-wide.
- The mesh has no handshake, no per-sender identity, no TLS, and assumes a small
  set of trusted, co-operated nodes. Pools are semi-trusted third parties on the
  public internet.
- FEC/segmentation/pacing are relay concerns that should stay server-side and
  evolve without a miner client update.

Instead, the relay exposes a small **authenticated HTTP/1.1 "block injection
endpoint"**, and the relay internally calls the §2.6 seam.

**Request**

```
POST /v1/inject/block HTTP/1.1
Host: <relay>
Content-Type: application/octet-stream
Content-Length: <n>
X-Sovright-Miner-Id: <opaque miner/pool id>       # selects the key server-side
X-Sovright-Timestamp: <unix seconds>              # replay window
X-Sovright-Nonce: <hex 16 bytes>                  # replay dedup
X-Sovright-Auth: <hex HMAC-SHA256>                # over the canonical preimage

<raw serialized Zcash block bytes>
```

**Canonical signing preimage** (length-delimited so no field boundary is
ambiguous):

```
miner_id "\n" timestamp "\n" nonce_hex "\n" body_len "\n" <raw body bytes>
```

`X-Sovright-Auth = hex(HMAC-SHA256(miner_key, preimage))`. The MAC covers the
full body, so the relay authenticates the exact bytes it is about to flood.

**Responses**

| Status | Meaning |
|--------|---------|
| `202 Accepted` | Auth + PoW + structure OK; handed to the flood seam. Body: `{"block_hash": "...", "mode": "raw_block_segments\|compact_block\|deduplicated"}` |
| `208 Already Reported` | Valid but already seen (dedup); not re-flooded. |
| `400 Bad Request` | Malformed block / wrong length / unparseable. |
| `401 Unauthorized` | Unknown miner id, bad MAC, or stale/replayed timestamp+nonce. |
| `422 Unprocessable Entity` | **Equihash PoW invalid** (see §5). |
| `429 Too Many Requests` | Rate limit exceeded for this miner. |

### 3.1 Why HTTP/1.1 (+ TLS in prod) over raw TCP or the UDP mesh

- **Universally implementable.** Every pool stack (ckpool, custom, Stratum
  proxies) can already make an HTTP POST; no need to link a Rust mesh client.
- **Full-block delivery wants reliable, ordered bytes.** A block is 2 KB–2 MB; a
  miner has exactly one copy and must deliver it intact. TCP gives that for free.
  The *relay→mesh* leg keeps UDP+FEC (loss-tolerant, latency-optimized) where it
  belongs; the *miner→relay* leg is a single reliable hop.
- **TLS termination is standard.** Production runs this behind TLS (rustls or a
  reverse proxy) for confidentiality + server auth; the HMAC still provides miner
  auth and message integrity independent of TLS.
- **Debuggable / observable.** Status codes map cleanly to reject reasons; curl
  works for ops.

We keep the payload as raw octet-stream (not JSON/hex) to avoid a 2× size blow-up
and a decode step on the hot path. The PoC CLI accepts hex for convenience and
decodes before sending.

## 4. Auth: per-miner keys

- Each authorized miner/pool gets a **32-byte secret key** and an opaque
  `miner_id`. Keys are per-miner (not the mesh PSK), so revoking one pool never
  touches the mesh or other pools.
- **HMAC-SHA256** over the canonical preimage — the identical primitive and key
  size the mesh already uses (`session.rs:27,153`), so we reuse vetted code
  patterns and the `hmac`/`sha2` crates already in the tree. (ed25519 is a
  reasonable alternative if pools prefer asymmetric keys / want the relay to hold
  only public keys; HMAC is simpler and matches existing code. The wire format
  isolates the auth tag in one header, so swapping to an ed25519 signature later
  is a localized change.)
- **Replay protection:** relay rejects requests whose `timestamp` is outside a
  ±N-second window (e.g. 30 s) and remembers `(miner_id, nonce)` for that window,
  rejecting repeats — mirroring the mesh's per-chunk seen-set.
- **Key management:** relay loads a `miner_id -> key` map from config
  (env/file), mirroring `parse_auth_key` (`p2p-ingress/config.rs:259`,
  `relay-node.rs:147`) — 32-byte hex, all-zero rejected. Rotation = add new key,
  drain, remove old.

## 5. SECURITY — this is a block-flooding amplifier

A single authenticated POST fans out FEC segments to every relay in every region.
An authed-but-buggy or malicious miner could otherwise spray fleet-wide garbage.
The endpoint MUST therefore validate **before** touching the flood seam. Order of
checks (cheapest / most-abusive-first):

1. **Auth first (§4).** No MAC, no work. Unauthenticated bytes are never parsed
   or flooded. This bounds the abuse set to known miners (accountable, revocable).
2. **Rate-limit per miner.** Token-bucket keyed on `miner_id` (e.g. a few
   injections/sec, small burst). Blocks are found ~once/75 s network-wide, so a
   legitimate pool injects rarely; anything faster is abuse or a bug. Excess →
   `429`. A global limiter caps aggregate mesh amplification regardless of how
   many keys are compromised.
3. **Structural validation.** Length ≥ `ZCASH_FULL_HEADER_SIZE`
   (`transport/pow.rs`), header parses, tx count compact-size sane, total size
   within the relay frame budget. Malformed → `400`.
4. **Equihash PoW validation — the core defense.** Reuse the in-repo validator.
   Two options, both present:
   - Relay-native `EquihashPowValidator` (`transport/pow.rs`), the same type the
     mesh nodes already run, taking the full header bytes and returning
     `PowResult::{Valid,Invalid,Indeterminate}`.
   - `zcash-equihash-validator`: `EquihashValidator::verify_solution(header_140,
     solution_1344)` (`validator.rs:56`), or `verify_share(header, solution,
     target)` (`validator.rs:95`) which *also* checks the block hash meets the
     difficulty `target` (derive `target` from the header `bits` via
     `compact_to_target`). Using `verify_share` additionally rejects a valid
     Equihash solution that does not actually clear network difficulty.

   **Invalid PoW → `422`, drop, do NOT flood, and increment `pow_rejected`.**
   Repeated PoW failures from one miner should trip a circuit-breaker (temp-ban
   the key) — a correct miner never submits invalid PoW.
5. **Dedup (don't re-flood).** Check the block hash against the same
   first-seen-wins ring the bridge uses (`relay_bridge.rs:185`). Already seen →
   `208`, no re-flood. This also collapses the race where the miner injects *and*
   the block arrives via gossip a moment later (§8). Belt-and-suspenders: the mesh
   node's own per-chunk PoW gate (§2.4) and the client-side `recent_delivered`
   set (`client.rs:233`) still protect the fleet even if the endpoint check is
   bypassed.

**Residual risk & mitigations**

- *Compromised miner key:* bounded by per-key + global rate limits and PoW
  validation (attacker must do real Equihash work per injected object); revoke the
  key. Nothing an attacker submits propagates unless it has valid PoW, so the
  worst case is amplification of *valid* blocks (which the mesh wants anyway) up
  to the rate limit.
- *Valid-PoW-but-off-chain block (stale/side fork):* still costs the attacker real
  work; dedup + Zebra's own `submitblock` validation (and the sidecar gate's
  parent-known / height-window, `submit_gate.rs`) contain it. Rate limits cap the
  spam volume.
- *Endpoint DoS (connection flood):* standard HTTP front (TLS, conn limits,
  timeouts, max body size) + auth-before-parse.

## 6. Flow (end to end)

```
1. Miner finds block; local zebrad/pool serializes it.
2. Miner POSTs raw block to nearest relay /v1/inject/block with HMAC auth.
      └─ sovright-miner-injector (PoC client, §7)
3. Relay injection endpoint:
      a. verify HMAC + timestamp/nonce            -> 401 on failure
      b. per-miner + global rate limit            -> 429 on failure
      c. structural checks                         -> 400 on failure
      d. Equihash PoW (EquihashPowValidator /      -> 422 on failure, pow_rejected++
         zcash-equihash-validator::verify_share)
      e. dedup ring (first-seen-wins)              -> 208 if already seen
4. Relay hands bytes to the SAME flood seam as gossip ingress:
      RelayBridge::forward_block(block_bytes, None)   (relay_bridge.rs:163)
        └─ split_raw_block / compact_block_to_chunks
        └─ FEC encode -> HMAC per chunk -> UDP fan-out to all relay peers
                                                        (client.rs:350)
5. Every relay node PoW-re-validates each chunk and re-floods inter-region
      (node.rs:443,590) — split-horizon prevents loops.
6. Each region's sidecar reassembles + submitblock to its local Zebra
      (main.rs:465, submit.rs:439, rpc.rs:153), behind the cheap SubmitGate.
7. Region Zebras accept the block via submit_block BEFORE native gossip arrives.
```

Step-to-code map:

| Step | Hooks in at |
|------|-------------|
| 2 | `sovright-miner-injector` CLI → HTTP POST |
| 3a–3e | **new** injection endpoint in `sovright-relay` (see §7a) |
| 3d | `sovright-relay::EquihashPowValidator` / `zcash-equihash-validator` |
| 4 | `RelayBridge::forward_block` `relay_bridge.rs:163` → `BlockSender` `client.rs:45/53` |
| 5 | `RelayNode` `node.rs:443` |
| 6 | `sovright-relay-sidecar` `main.rs:465`, `submit.rs:439`, `rpc.rs:153` |

## 7. Components to build

### (a) Relay-side injection endpoint — **new, to build** (`sovright-relay`)

- A small async HTTP server (behind TLS in prod) mounted on the relay-node
  binary, or a thin sidecar process co-located with each relay. It holds:
  - a `miner_id -> [u8;32]` key map (config),
  - a token-bucket rate limiter (per-miner + global),
  - an `EquihashPowValidator`,
  - a `BlockSender` (or a cloned `RelayBridge`) into the local mesh client.
- On a valid request it calls `forward_block(bytes, None)` (or
  `split_raw_block` + `send_raw_block_segment`) — the §2.6 seam — and maps the
  `ForwardMode`/error to the HTTP status table in §3.
- Reuses: `EquihashPowValidator`, `split_raw_block`, `BlockSender`, the dedup ring
  type, and `parse_auth_key`-style key loading. Net-new: HTTP glue, per-miner key
  map, rate limiter, replay window. Estimated small–medium.

### (b) Miner-side client — **scaffolded (PoC)** (`sovright-miner-injector`)

See §7 below / `crates/sovright-miner-injector`. Rust, matches the stack, no new
deps.

### (c) Config / auth-key management

- Relay: `SOVRIGHT_RELAY_INJECT_KEYS` (e.g. path to a `miner_id=hex32` file) +
  `SOVRIGHT_RELAY_INJECT_BIND_ADDR`, `_RATE_PER_SEC`, `_REPLAY_WINDOW_SECS`,
  `_TLS_CERT/_KEY`.
- Miner: `--relay/--miner-id/--key-hex` flags or `SOVRIGHT_INJECT_*` env
  (implemented in the PoC).
- Key issuance is out-of-band (ops hands each pool an id+key); rotation by
  add-drain-remove.

### (d) Metrics (Prometheus, alongside existing relay metrics)

| Metric | Where |
|--------|-------|
| `injections_received_total{miner_id}` | endpoint entry |
| `injections_auth_failed_total{reason}` | 401 |
| `injections_rate_limited_total{miner_id}` | 429 |
| `injections_pow_rejected_total{miner_id}` | 422 (the abuse signal) |
| `injections_deduplicated_total` | 208 |
| `injections_flooded_total{mode}` | after `forward_block` success |
| `injection_to_flood_seconds` (histogram) | receive→flood latency |

Emit through the relay's existing `render_prometheus_text` path
(`relay/metrics.rs`).

## 8. Coexistence with gossip ingress, failure modes, rollback

- **Both paths feed one mesh.** Miner injection and `p2p-ingress` both terminate
  at `forward_block`, which is idempotent per block hash via first-seen-wins
  dedup (`relay_bridge.rs:185`). Whichever path sees the block first floods it;
  the other is deduped (`208` / `ForwardMode::Deduplicated`). No double-flood.
  Defense in depth: the mesh node's per-chunk PoW gate and `recent_delivered`
  set independently suppress duplicate propagation.
- **Failure modes**
  - *Relay/endpoint down:* miner's POST fails fast; block still propagates the old
    way via gossip ingress. Injection is a pure accelerator, never a dependency
    for correctness.
  - *Miner sends garbage / bad PoW:* rejected at the endpoint (`400/422`), never
    flooded; alert on `pow_rejected`.
  - *Injected block loses the race to gossip:* deduped, harmless.
  - *Key compromise:* rate limits + PoW cap blast radius; revoke key.
- **Rollback:** feature-flag the endpoint (`SOVRIGHT_RELAY_INJECT_ENABLED`,
  default off). Disable = stop binding the port; gossip ingress path is
  untouched. No schema/state migration, so rollback is a restart.

## 9. Phase-3 PoC status

- **Built:** `crates/sovright-miner-injector` — miner-side CLI
  (`sovright-inject-block`) + library. Reads a hex block from file/stdin, builds
  the authenticated request per §3, and POSTs it over TCP. `--dry-run` prints the
  raw HTTP request for inspection. Compiles, clippy-clean, 8 unit tests
  (auth known-vector, tamper-detection, header assembly, response parsing).
- **Stubbed / to build:** the relay-side endpoint (§7a) — documented, not
  implemented. The PoC intentionally uses only crates already vendored
  (`hmac`, `sha2`, `hex`) + std TCP; TLS and a CSPRNG nonce are documented
  follow-ups.
