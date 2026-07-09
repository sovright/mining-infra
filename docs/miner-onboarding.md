# Miner Relay Onboarding

**Status:** RFC (design). Supersedes the earlier "miner-direct block injection HTTP
endpoint" design — see §11 for what changed and why.
**Author:** R&D
**Related crates:** `sovright-relay` (mesh node + transport), `sovright-relay-sidecar`,
`sovright-p2p-ingress`, `zcash-equihash-validator`; **new:** an enrollment service
(HTTPS) and a local-inject hook.

## 1. Motivation

A freshly-found block reaches our mesh today only *after* it has propagated through
native Zcash P2P gossip and been picked up by `sovright-p2p-ingress`. Because we are
downstream of gossip, we win the first-to-Zebra race in only ~8% of blocks — a
listener-relay can arbitrate geography but cannot beat the block's own origin.

**The structural lever:** let the miner/pool that *found* the block put it onto the
mesh at the point of origin, before gossip even starts. The cleanest way to do that
is **not** a bespoke ingest endpoint on our relays — it is to let the miner **run
their own relay node and join the mesh as a first-class, authenticated peer.** When
the miner finds a block, their own relay node floods it to the whole mesh over the
existing FEC/UDP transport. The block enters at t=0, at the origin, and every
region's Zebra can `submitblock` it before gossip arrives.

```
                        ┌──────── today ────────┐
 miner ─> local zebrad ─> P2P gossip ─> p2p-ingress ─> relay mesh ─> all-region Zebra
                                                          (we start here, ~8% wins)

                        ┌──── this proposal ────┐
 miner's own relay node ─────────────────────────> relay mesh ─> all-region Zebra
   (local inject, then flood over the mesh it     (we start at the origin, t=0)
    is already an authenticated peer of)
```

This also makes the benefit **bidirectional**: a miner who runs a mesh node also
*receives* every other block on the mesh at mesh speed, so their own Zebra/mining
tracks the tip faster too.

## 2. How a block floods on the mesh today (what the miner's node reuses)

Investigated in `sovright-relay`. A miner's relay node is the *same binary* our
relays run, so it inherits all of this unchanged:

- **Injection primitive:** `RelayClient::sender()` → `BlockSender`
  (`crates/sovright-relay/src/relay/client.rs:39,168`):
  - `BlockSender::send(CompactBlock)` (`client.rs:45`)
  - `BlockSender::send_raw_block_segment(RawBlockSegment)` (`client.rs:53`)
  Both enqueue a `RelayPayload` drained by `RelayClient::run_with_outgoing`
  (`client.rs:213`). This is the exact seam `sovright-p2p-ingress` uses via
  `RelayBridge::forward_block` (`relay_bridge.rs:163`).
- **Flood:** compact blocks → `compact_block_to_chunks` (`chunker.rs:296`); raw
  blocks → `split_raw_block` (`segmented_block.rs:173`) → per-segment chunks. Then
  Reed–Solomon FEC (`fec/encoder.rs:49`, prod 224+32) → HMAC per chunk → UDP fan-out
  to every mesh peer (`send_chunks_internal`, `client.rs:350`).
- **Transport auth:** every chunk is HMAC-SHA256-keyed and constant-time verified
  (`transport/session.rs:119,161`), with a per-`(block_hash, chunk_id)` replay set,
  120 s TTL.
- **PoW gate at every hop:** a relay node re-floods **only PoW-valid** assemblies —
  `process_chunk_for_session` → `validate_pow_from_assembly` (`node.rs:590`) runs
  Equihash over the reconstructed header, and only `pow_validated` assemblies emit to
  `forward_to_peers` (`node.rs:413-443`). **This is the load-bearing safety property
  for onboarding:** admitting an external peer cannot inject junk into the mesh,
  because every node — ours and theirs — refuses to propagate anything that fails
  Equihash.
- **Sidecar submit is unchanged:** reassembled blocks reach Zebra `submitblock`
  through the existing sidecar path behind the cheap `SubmitGate`
  (`submit.rs:439`, `rpc.rs:153`, `submit_gate.rs`).

### 2.1 The mesh already supports a *set* of per-peer keys

This is the key finding that makes onboarding small. The mesh does **not** hardcode a
single shared secret at the protocol level:

- `RelayConfig.authorized_keys` is a **collection**, not a scalar
  (`with_authorized_keys(vec![...])`); admission is `authorized_keys.contains(key)`
  (`RelayNode::is_authorized`, `node.rs:137-138`).
- When a datagram arrives from a new source, the node **tries each authorized key**
  to establish the session and keys that session to whichever key verified
  (`node.rs:778-795`, `898-915`). Each `RelaySession` HMACs with its own `auth_key`
  (`session.rs:119`).

Today the whole fleet happens to load one shared key into that set. **Per-miner keys
therefore require no protocol or handshake change** — a miner simply presents a key
that is *also* in our relays' `authorized_keys`, and the mesh accepts them. The only
gaps are (a) making `authorized_keys` **dynamically updatable** (it is static config
today) and (b) associating each key with a miner identity for accounting/revocation.

## 3. Architecture

Three pieces. Only the enrollment service and the local-inject hook are net-new; the
mesh node itself is reused.

1. **Miner-run relay node** — the existing `relay-node` binary, deployed by the pool
   in their own infra, configured with (i) the mesh peer endpoints to connect to and
   (ii) *their own* 32-byte mesh key. Once that key is in our relays'
   `authorized_keys`, the node is a full mesh peer: it injects and it receives.
2. **Enrollment service (HTTPS)** — a small service *we* run. It validates an invite
   code, accepts the miner-generated key, and writes it into the mesh key store that
   our relays read. This is the only new networked attack surface, and it never
   handles blocks — only key registration.
3. **Local-inject hook** — a loopback-only interface on the miner's own relay node so
   the pool's block-found path can hand a freshly serialized block to *its own* node
   for immediate flood. Because it is localhost on the miner's own machine, it needs
   no cross-network auth.

## 4. Onboarding flow (the core of this RFC)

```
0. Ops issues the pool an INVITE CODE (single-use, expiring) out of band.
1. Pool deploys the relay-node binary in their infra.
2. On first start, the node GENERATES a fresh random 32-byte mesh key locally.
   The private material never leaves the miner's host except in step 3 (over TLS).
3. The node calls our ENROLLMENT SERVICE over HTTPS:
      POST https://enroll.<our-domain>/v1/enroll
      { invite_code, miner_id, mesh_key (32B hex), node_endpoint (ip:port), pubkey_fpr }
4. Enrollment service:
      a. validate invite_code: exists, unused, unexpired         -> 401/409 on failure
      b. rate-limit + structural checks on the key                -> 400/429
      c. register { miner_id -> mesh_key, node_endpoint } in the
         authorized-key store; mark the invite code CONSUMED
      d. return the mesh connect info (relay peer endpoints,
         mesh params) + the assigned miner_id
5. Our relays pick up the new key (store reload, §6) and now ACCEPT the miner's
   node as an authorized mesh peer; the relays also add the miner node_endpoint
   to their fan-out peer set so blocks flow both directions.
6. Miner's node connects to the mesh peers and is live: it floods blocks it finds
   and receives blocks others flood. No further human step.
```

The property the user asked for — *"the relayer generates a key and sends it over
HTTPS and the key is automatically added to the mesh if the invite code was valid"* —
is steps 2→5, fully automated after the one out-of-band invite.

### 4.1 Key generation & custody

- **The miner generates the key**, from a CSPRNG (`getrandom`), on their own host.
  We never generate or escrow it. It is a 32-byte secret for the mesh's HMAC-SHA256.
- It is transmitted to us **once**, over **TLS** (server-authenticated HTTPS), inside
  the enroll request. We store it in the authorized-key store (encrypted at rest,
  e.g. GCP Secret Manager or a KMS-wrapped file) exactly as we store our own mesh key.
- Because the mesh transport is symmetric HMAC, both ends must hold the same key;
  the miner holds it (to sign) and our relays hold it (to verify). This mirrors how
  the fleet shares keys today, but now **scoped per miner** so revoking one never
  touches another. (An asymmetric handshake — Noise/ed25519 so we hold only public
  keys — is a strictly-better future evolution; see §10. It is *not* required for v1
  and would be a real transport change, whereas the symmetric per-key model ships on
  the mechanism that already exists per §2.1.)

### 4.2 Invite codes

- **Single-use, expiring, high-entropy** (≥128 bits). Issued by ops to a vetted pool
  (a business relationship, not open registration). One code enrolls one node.
- Stored server-side with state `{issued → consumed | expired | revoked}` and the
  pool it was issued to. `enroll` consumes it atomically (so a leaked-but-used code
  can't enroll a second node).
- An invite authorizes *adding a key to the mesh* — so it is a sensitive credential;
  treat issuance like handing out a mesh seat. Rotating/revoking a pool = revoke its
  key(s) (§7), independent of the (already-consumed) invite.

## 5. The enrollment service (new)

A small HTTPS service (rustls or behind a TLS-terminating proxy) that we operate. It
is deliberately tiny and **touches no block data** — its whole job is invite
validation + key registration.

**`POST /v1/enroll`**

| Field | Meaning |
|-------|---------|
| `invite_code` | single-use code (§4.2) |
| `miner_id` | requested opaque id (server may assign/override) |
| `mesh_key` | 32-byte hex, miner-generated; all-zero rejected |
| `node_endpoint` | `ip:port` the miner's node will send/receive on |

| Status | Meaning |
|--------|---------|
| `200 OK` | enrolled; body = `{miner_id, mesh_peers:[...], mesh_params}` |
| `400` | malformed key/endpoint |
| `401` | unknown/expired invite |
| `409` | invite already consumed |
| `429` | rate-limited |

Also: `DELETE /v1/enroll/{miner_id}` (ops-authenticated) to revoke, and
`GET /v1/enroll/{miner_id}` for status. The service writes to the same
authorized-key store the relays read (§6) and emits metrics
(`enroll_success_total`, `enroll_rejected_total{reason}`, `enrolled_miners`).

## 6. Making `authorized_keys` dynamic (the one real mesh change)

Today `authorized_keys` is loaded once from static config. To let enrollment add a
key without redeploying the fleet:

- Back `authorized_keys` with a **reloadable store** — the enrollment service writes
  `{miner_id -> key, endpoint, state}`; relays load it at start and **reload on
  change** (file watch + `SIGHUP`, or a short poll of the store). Revocation =
  remove/flip-to-revoked → reload → the key stops verifying and the peer is dropped.
- Associate each key with `miner_id` so metrics, rate limits, and revocation are
  per-miner (today keys are anonymous set members). Small struct change around
  `authorized_keys`; `is_authorized`/session setup stay as-is (`node.rs:778-795`).
- Add the miner's `node_endpoint` to the relay's **outbound peer set** so blocks fan
  out to the miner too (bidirectional). Also reloadable.

Net mesh change: `authorized_keys` set → reloadable per-miner keyed store, + peer-set
reload. No transport/handshake/PoW change.

## 7. Local block injection on the miner's node (new, small)

The miner's node must flood the block *it* found, not wait to hear it over P2P. Add a
**loopback-only inject interface** to the relay-node binary:

- A localhost listener (Unix socket or `127.0.0.1` TCP), enabled only on miner
  deployments, that accepts a raw serialized block and calls the §2 seam
  (`forward_block` / `split_raw_block` + `send_raw_block_segment`).
- **No cross-network auth needed** — it is the miner's own host; OS permissions on
  the socket are the boundary. The pool's block-found hook (ckpool notify, a
  Stratum-proxy shim, or `zebrad`'s block-notify) writes the block to it.
- It still passes through the same local PoW/dedup the mesh applies, so even a buggy
  local caller cannot flood invalid blocks.

## 8. Security

The trust model shifts from "closed fleet of co-operated relays" to "closed fleet +
vetted external peers." That expansion is bounded by five independent controls:

1. **Vetting + invite codes.** Enrollment is not open; a pool must be issued a
   single-use invite. No invite → no key → no mesh seat.
2. **Per-miner keys, revocable, isolated.** Each miner has its own key; compromise or
   revocation of one never affects the fleet key or other miners (§6). This is the
   concrete win over sharing the fleet PSK.
3. **PoW gate at every hop (unchanged, §2).** An admitted peer still cannot inject
   junk — every node refuses to propagate anything failing Equihash. Worst case an
   abusive peer floods *valid* blocks (which the mesh wants) up to a rate limit.
4. **Rate limiting / fan-out caps.** Per-peer and global limits on injected objects
   and on how far a single peer's traffic fans out, so a compromised key can't turn
   the mesh into an amplifier. Blocks are found ~once/75 s network-wide; anything
   faster from one peer is abuse or a bug.
5. **TLS + atomic invite consumption** on the enrollment path; the mesh key transits
   encrypted once and is stored like our own secrets (§4.1).

**Residual risks & mitigations**
- *Compromised miner key* → attacker can inject/receive as that miner; bounded by
  PoW + rate limits, contained by revoking the one key.
- *Malicious peer floods valid stale/side blocks* → costs real Equihash work per
  object; dedup + Zebra `submitblock` validation + the sidecar gate (parent-known /
  height-window) contain it; rate limits cap volume.
- *Enrollment abuse (invite theft)* → single-use + expiry + atomic consume + revoke;
  invites are issued to accountable partners only.
- *Mesh eavesdropping by a peer* → blocks are public data; no confidential mesh state
  is exposed by peer membership.

## 9. Components to build

| # | Component | Where | Size |
|---|-----------|-------|------|
| 1 | Dynamic/reloadable per-miner `authorized_keys` + peer set | `sovright-relay` (`node.rs`, config) | small–medium |
| 2 | Enrollment service: invite validation + key registration + revoke | new crate/service | medium |
| 3 | Local-inject loopback interface on `relay-node` | `sovright-relay` bin | small |
| 4 | Node bootstrap: generate key on first start, call enroll, persist config | `relay-node` | small |
| 5 | Authorized-key store (Secret Manager / KMS-wrapped file) + reload wiring | infra + `sovright-relay` | small–medium |
| 6 | Deployment bundle + docs for pools (run the node, firewall the mesh UDP to allowlisted relays, wire block-notify) | deployment repo | medium |
| 7 | Metrics: `enrolled_miners`, per-miner inject/receive counters, `enroll_rejected` | `sovright-relay` + service | small |

**Reused as-is (no change):** the entire flood path (`BlockSender`, chunker, FEC,
UDP fan-out), the HMAC transport, the per-hop Equihash PoW gate, session setup
(`node.rs:778-795`), the sidecar submit path.

## 10. Rollout / phasing

1. **Phase 1 — dynamic keys (internal).** Make `authorized_keys` reloadable + keyed
   by miner (component 1, 5). Ship dark; validate by rotating a fleet key with no
   restart. No external exposure yet.
2. **Phase 2 — enrollment service (staging).** Stand up the enroll service against a
   staging key store; enroll a *test* node we control; confirm it joins the mesh and
   both injects and receives. (Component 2, 4.)
3. **Phase 3 — local inject + one friendly pool.** Add the loopback inject
   (component 3), onboard a single trusted pool behind a feature flag, measure the
   first-to-Zebra win-rate delta for blocks they find.
4. **Phase 4 — general availability.** Deployment bundle + docs (component 6),
   per-miner metrics/alerts, revocation runbook. Widen to more pools.

Everything is a pure accelerator: if a miner node or the enroll service is down,
blocks still propagate via gossip ingress. Nothing here is on the correctness path.

## 11. What changed from the earlier "HTTP injection endpoint" design

The prior RFC put an authenticated **HTTP block-injection endpoint** on our relays:
miners POSTed raw blocks to us over per-miner HMAC, and we PoW-validated and flooded.
This design replaces that with **miners running their own mesh node**. Why:

- **Less net-new code.** The old design required a whole new HTTP server + per-miner
  request auth + rate limiter on the relay hot path. The mesh already accepts a *set*
  of keyed peers (§2.1), so onboarding reuses the flood/transport/PoW path entirely;
  the new code is an enroll service + a reload + a localhost hook.
- **Injection at the true origin.** The block enters the mesh *at the miner*, not
  after a hop to one of our relays — strictly faster.
- **Bidirectional benefit.** A mesh peer also receives blocks fast; an HTTP submitter
  does not.
- **Simpler auth story.** The sensitive cross-network surface shrinks to a tiny
  enroll service that never touches blocks; block injection becomes a *localhost*
  call on the miner's own box (no cross-network block auth at all).

The old miner-side `sovright-miner-injector` PoC (an HTTP client) is therefore
**retired** in favor of the miner running `relay-node` + the loopback inject hook;
its Equihash/validation reasoning carries over as the per-hop PoW gate that already
exists on every node. The security analysis (PoW-as-load-bearing, per-miner keys,
rate limits) is preserved and, if anything, strengthened by removing the bespoke
ingest endpoint.

