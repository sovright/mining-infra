# Tier-2 Functional Core + Public Images Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Tier-2 actually mine miner-declared templates (JDC downstream listener + real share path) and publish the two Docker images the sovereignty bundle references.

**Architecture:** The JDC (`zcash-jd-client`) gains a downstream V2 listener serving exactly its declared job to the existing `sovright-v1-stratum-proxy`; shares relay to the pool over the JD connection via a new `SubmitSharesJd` message validated server-side with the same machinery as `PushSolution`; block-target hits are assembled and submitted to the miner's own Zebra. Both binaries get env-var config, Dockerfiles, and a GHCR publish workflow; the product bundle is realigned to the now-real topology.

**Tech Stack:** Rust (tokio, clap with `env` feature), `zcash-mining-protocol` codec, GitHub Actions → ghcr.io, docker multi-stage builds.

**Spec:** `docs/superpowers/specs/2026-06-04-tier2-functional-core-images-design.md`

---

## Repos / worktrees

| Repo | Path | Branch |
|---|---|---|
| mining-infra (bedrock) | `/Users/zakimanian/code/zcash-work/bedrock/.claude/worktrees/tier2-images` | `feat/tier2-images` (exists; sovright/main + JD-env cherry-pick) |
| Product portal | `/Users/zakimanian/code/zcash-work/Sovright-Mining-Pool` | create worktree `.worktrees/tier2-bundle-images`, branch `feat/tier2-bundle-images` off `main` (Task 8) |

All mining-infra commands run from the tier2-images worktree root. CI on this repo runs `cargo build --workspace --all-targets`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo fmt --all -- --check` — every task must keep all four green (run at minimum the targeted tests + `cargo fmt --all` before each commit; run the full quartet before pushing).

## Pre-verified facts (trust these; file refs are in this worktree)

- **V2 mining protocol** (`crates/zcash-mining-protocol`): four messages only — `NewEquihashJob` 0x20, `SubmitEquihashShare` 0x21, `SubmitSharesResponse` 0x22, `SetTarget` 0x23. 6-byte `MessageFrame` header (extension_type u16 LE, msg_type u8, length u32-as-3-bytes LE). No handshake/channel-open: channels are implicit via `channel_id`. Full field lists in `src/messages.rs`; encode/decode fns in `src/codec.rs` (`encode_new_equihash_job`, `decode_submit_share`, `encode_submit_shares_response`, `encode_set_target`, …). `RejectReason`: StaleJob/Duplicate/InvalidSolution/LowDifficulty/Other(String).
- **Proxy upstream behavior** (`crates/sovright-v1-stratum-proxy/src/session.rs`): on connect it reads until the first `NewEquihashJob` (line ~655) — `SetTarget` may arrive before it; per-V1-miner it adopts `channel_id`, `nonce_1`, `nonce_2_len`, `target` from the job; submits `SubmitEquihashShare` (sequence-number matched) and expects `SubmitSharesResponse`. Plain TCP only. Config merge: file → `apply_overrides()` from CLI flags (`main.rs:73-82`).
- **JD protocol** (`crates/zcash-jd-server`): message IDs 0x50-0x5A in `src/messages.rs:14-38` (next free: **0x5B**). Codec helpers `write_string`/`write_bytes_u16`/`write_bytes_u32` + LE ints in `src/codec.rs`; frame uses `JD_EXTENSION_TYPE`. Dispatch: `handle_jd_client_with_transport()` match in `src/server.rs:~1015-1168`. `JdTransport::{Plain,Noise}` with `read_full_message`/`write_full_message`.
- **Declared-job storage**: `TokenManager` keyed by token; `DeclaredJobInfo { job_id, client_id, mode, channel_id, version, prev_hash, merkle_root, block_commitments, bits, time, coinbase_tx }` (`src/token.rs:30-54`); lookup `token_manager.find_job_by_id(job_id)`; tokens expire after `config.token_lifetime` (default 5 min) — this IS the stale-job window, no new eviction needed.
- **`handle_push_solution`** (`src/server.rs:476-542`): consumes `solution.{job_id, channel_id, version, time, nonce, solution}`; header bytes [0:4]=version LE, [4:36]=prev_hash, [36:68]=merkle_root, [68:100]=block_commitments, [100:104]=time LE, [104:108]=bits LE, [108:140]=nonce — version/prev/merkle/commitments/bits from stored job, time+nonce from submission; verifies `EquihashValidator::verify_share(&header, &solution.solution, &target)` against `compact_to_target(job.bits)` (the **block** target); credits `payout_tracker.record_share(&job.client_id, difficulty)`.
- **CRITICAL GAP the plan closes:** nothing grants a *share* target for declared jobs — `SetCustomMiningJobSuccess { channel_id, request_id, job_id }` carries no target, and the JD validation path only knows the block target. Task 2 adds the grant.
- **jd-client** (`crates/zcash-jd-client`): `JdClientConfig` fields in `src/config.rs:46-77`; client loop + state (current_token/current_job_id/granted_mode) in `src/client.rs:98-399`; `TemplateBuilder.build_coinbase/calculate_merkle_root`; `block_submitter::build_block_hex(header, solution, coinbase_tx, transactions) -> String` exists (assembly + submitblock wrapper). The JDC's template comes from its own Zebra so it holds full tx data for assembly.
- **Tests/CI**: JD server test style in `crates/zcash-jd-server/tests/integration_tests.rs` (sync `test_config()` + `#[tokio::test]` handlers + codec round-trips); in-process pool e2e pattern in `crates/zcash-pool-server/tests/e2e_mining_flow.rs`. CI in `.github/workflows/ci.yml` (stable toolchain, build/test/clippy/fmt). No Dockerfiles on this branch. Workspace `edition = "2024"`, resolver 3.
- **Test miner** (`crates/zcash-test-miner`): `--v1` mode speaks V1 JSON-RPC at `--pool_addr` and CPU-solves real Equihash — the integration-test driver.
- **clap `env` support** requires the `env` feature on the clap dependency — check `Cargo.toml` workspace dep and enable if absent (one line; do it in the first task that needs it).

## File structure (new/modified)

```
mining-infra:
  crates/zcash-jd-server/src/messages.rs        # + SubmitSharesJd, SubmitSharesJdResponse, share_target on Success
  crates/zcash-jd-server/src/codec.rs           # + codecs for the above; Success codec gains share_target
  crates/zcash-jd-server/src/server.rs          # + handle_submit_shares_jd, dispatch arm, share-target grant, per-job dedup
  crates/zcash-jd-server/src/token.rs           # DeclaredJobInfo + share_target
  crates/zcash-jd-client/src/config.rs          # + jdc_listen, policy_path; env-able
  crates/zcash-jd-client/src/main.rs            # env attrs, policy load, listener spawn
  crates/zcash-jd-client/src/policy.rs          # NEW: policy.toml parse/enforce-scope
  crates/zcash-jd-client/src/listener.rs        # NEW: downstream V2 listener (sessions, jobs, share intake)
  crates/zcash-jd-client/src/share_path.rs      # NEW: share validation, dedup, relay, block path
  crates/zcash-jd-client/src/client.rs          # expose declared-job/share-target state to listener; relay sender
  crates/sovright-v1-stratum-proxy/src/main.rs  # env attrs (SV1_LISTEN, UPSTREAM)
  docker/Dockerfile.job-declarator              # NEW
  docker/Dockerfile.translator-proxy            # NEW
  .github/workflows/images.yml                  # NEW
product (Sovright-Mining-Pool):
  sovright-api/src/api/bundle.rs                # image refs, env wiring, trimmed policy.toml, README roadmap note
```

---

### Task 1: Proxy env vars (`SV1_LISTEN`, `UPSTREAM`)

**Files:**
- Modify: `crates/sovright-v1-stratum-proxy/src/main.rs` (Args struct)
- Maybe modify: root `Cargo.toml` (clap `env` feature)

- [ ] **Step 1:** Check clap features: `grep -n 'clap' Cargo.toml crates/sovright-v1-stratum-proxy/Cargo.toml`. If `env` is not among the features, add it to the workspace clap dep (`features = [..., "env"]`).
- [ ] **Step 2:** Add env attributes to the two Args fields in `main.rs`:

```rust
    #[arg(long, env = "SV1_LISTEN")]
    listen: Option<SocketAddr>,

    #[arg(long, env = "UPSTREAM")]
    upstream: Option<SocketAddr>,
```
(Only these two — the bundle contract names only these. CLI precedence over env is clap's default behavior.)
- [ ] **Step 3:** Add a unit test in `main.rs`'s test module (create one if absent) using `Args::try_parse_from` plus `std::env::set_var` — note env-mutating tests must be serialized; follow any existing pattern in the repo, else name it so it runs alone and restore the vars at the end. Assert: env set + no flag → value from env; both → flag wins.
- [ ] **Step 4:** `cargo test -p sovright-v1-stratum-proxy` → PASS; `cargo fmt --all`.
- [ ] **Step 5:** Commit: `feat(proxy): SV1_LISTEN and UPSTREAM environment variables`

### Task 2: Share-target grant for declared jobs

**Files:**
- Modify: `crates/zcash-jd-server/src/messages.rs` (SetCustomMiningJobSuccess), `src/codec.rs`, `src/token.rs` (DeclaredJobInfo), `src/server.rs` (grant on declaration), config for the target value
- Test: `crates/zcash-jd-server/tests/integration_tests.rs`

- [ ] **Step 1 (failing tests):** (a) codec round-trip for `SetCustomMiningJobSuccess` including a `share_target: [u8; 32]` field; (b) declaration handler test asserting the success response carries the configured share target and the stored `DeclaredJobInfo` records it.
- [ ] **Step 2:** Run → FAIL (no field).
- [ ] **Step 3:** Implement:
  - `SetCustomMiningJobSuccess` gains `pub share_target: [u8; 32]` (32 raw bytes appended at the end of the payload in encode/decode — all encoders/decoders are in-repo; update the jd-client side decode in the same commit).
  - `DeclaredJobInfo` gains `pub share_target: [u8; 32]`.
  - `JdServerConfig` gains `pub share_target: [u8; 32]` with a default derived the same way the pool's stratum side derives its initial share target from `initial_difficulty` (reuse `difficulty_to_target` / `difficulty_to_target_with_max` from `zcash-equihash-validator/src/difficulty.rs`; don't reimplement). `run_pool_testnet.rs` may pass it explicitly later; default must be a sane testnet value (match the stratum side's initial difficulty 0.0001 conversion).
  - `handle_declare_job` (and the full-template path) stores the target in job info and returns it in the success message.
- [ ] **Step 4:** Run jd-server tests + `cargo test -p zcash-jd-client` (its decode changed) → PASS.
- [ ] **Step 5:** Commit: `feat(jd): pool grants per-job share target in SetCustomMiningJobSuccess`

### Task 3: `SubmitSharesJd` message + response (protocol only)

**Files:**
- Modify: `crates/zcash-jd-server/src/messages.rs`, `src/codec.rs`, `src/lib.rs` (exports)
- Test: codec round-trips in `tests/integration_tests.rs`

- [ ] **Step 1 (failing tests):** round-trips for both messages, including each error code and the empty-batch rejection.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement (follow the existing message/codec style exactly — LE ints, fixed arrays raw, `write_bytes_u16` for var-len):

```rust
pub const SUBMIT_SHARES_JD: u8 = 0x5B;
pub const SUBMIT_SHARES_JD_RESPONSE: u8 = 0x5C;

/// A batch of shares mined against a declared job, relayed by the JDC.
pub struct SubmitSharesJd {
    pub channel_id: u32,
    pub request_id: u32,
    pub job_id: u32,
    pub shares: Vec<JdShare>,          // u16 count prefix; reject 0 and > 64 at decode
}

/// One share: exactly the fields handle_push_solution consumes from a
/// submission (version/time/nonce/solution); header rest comes from the
/// stored DeclaredJobInfo.
pub struct JdShare {
    pub version: u32,
    pub time: u32,
    pub nonce: [u8; 32],
    pub solution: [u8; 1344],
}

pub struct SubmitSharesJdResponse {
    pub channel_id: u32,
    pub request_id: u32,
    pub accepted: u16,
    pub rejected: u16,
    /// First rejection's code when rejected > 0 (0 otherwise).
    pub first_error_code: u8,          // 0 none, 1 unknown_job, 2 stale_job,
                                       // 3 low_difficulty, 4 bad_solution,
                                       // 5 duplicate, 6 channel_mismatch
}
```
- [ ] **Step 4:** Run → PASS. Commit: `feat(jd): SubmitSharesJd batch share relay message pair`

### Task 4: Pool-side `SubmitSharesJd` handler

**Files:**
- Modify: `crates/zcash-jd-server/src/server.rs` (handler + dispatch arm + per-job dedup state)
- Test: `tests/integration_tests.rs`

- [ ] **Step 1 (failing tests):** drive `handle_submit_shares_jd` directly (style of existing handler tests): declare a job first (Task 2 test helper), then assert — valid share credits `payout_tracker` under the declaring client with difficulty derived from the job's **share_target**; unknown job_id → `unknown_job`; channel mismatch → `channel_mismatch`; share that fails Equihash → `bad_solution`; share above share target → `low_difficulty`; same share twice → second is `duplicate`; mixed batch returns correct accepted/rejected counts. **Known fact: no valid-solution fixture exists anywhere in the test suite** — existing tests (jd-server's `test_push_solution_rejects_invalid_solution`, pool's `e2e_mining_flow.rs` with `[0u8; 1344]`) only exercise rejection paths; the only real solver is in the test-miner binary. Therefore: cover every rejection path here, and leave the happy-path accepted-share assertion to Task 7 (which has a real solver). Do NOT invent a mock that bypasses `EquihashValidator`.
- [ ] **Step 2:** Run → FAIL (no handler).
- [ ] **Step 3:** Implement `handle_submit_shares_jd(&self, msg) -> SubmitSharesJdResponse`:
  - `find_job_by_id`, channel check (mirror `handle_push_solution`'s order; map lookup failures to codes instead of `Err`).
  - Per share: time-window check (same ±60/+7200 rule), header build (same byte layout, `share.time`/`share.nonce`), `EquihashValidator::verify_share` against `job.share_target` (NOT `job.bits`), dedup check, then `payout_tracker.record_share(&job.client_id, target_to_difficulty(&job.share_target))`.
  - Dedup state: `Mutex<HashMap<u32 /*job_id*/, HashSet<[u8; 32]>>>` keyed by `sha256(nonce ‖ time_le ‖ solution[..64])`; entries dropped when the token manager evicts the job (hook the existing cleanup; if no hook exists, clear entries for job_ids no longer resolvable at the start of each handler call — O(small)).
  - Dispatch arm in `handle_jd_client_with_transport`: decode, call handler, `write_full_message` the encoded response (this message DOES get a response, unlike PushSolution).
- [ ] **Step 4:** Run → PASS; `cargo clippy -p zcash-jd-server -- -D warnings`.
- [ ] **Step 5:** Commit: `feat(jd): validate and credit relayed declared-job shares`

### Task 5: JDC downstream listener + share path

The largest task. Read `crates/zcash-pool-server/src/session.rs` (frame loop) and `server.rs:620-784` (connection setup, job send) before starting — the listener is a stripped-down version of that structure serving ONE job stream.

**Files:**
- Create: `crates/zcash-jd-client/src/listener.rs`, `crates/zcash-jd-client/src/share_path.rs`
- Modify: `crates/zcash-jd-client/src/client.rs` (shared state + relay), `src/main.rs` (spawn), `src/config.rs` (`jdc_listen: Option<SocketAddr>`), `src/lib.rs`
- Test: `crates/zcash-jd-client/tests/listener_tests.rs` (new)

Design contract (from spec + recon):

- Shared state `Arc<DeclaredJobState>` owned by the client loop, read by the listener: `RwLock<Option<CurrentDeclaredJob>>` where `CurrentDeclaredJob { job_id, version, prev_hash, merkle_root, block_commitments, time, bits, share_target, coinbase_tx, transactions: Vec<Vec<u8>> }` — populated on every `SetCustomMiningJobSuccess` (client.rs:~376 has the template in scope there), cleared on disconnect from pool. **Heads-up:** the coinbase-only path (`handle_coinbase_only_job`) does NOT currently retain raw non-coinbase tx bytes — only the full-template path assembles them. You must capture the template's raw transaction data at declaration time (confirm the `BlockTemplate` type exposes raw tx bytes from getblocktemplate; thread them into `CurrentDeclaredJob`) or the block path cannot assemble. This is required work, not plumbing that already exists.
- Listener (`listener.rs`): tokio TcpListener on `config.jdc_listen` (only when Some). Per connection: assign `channel_id` (AtomicU32), derive a per-channel `nonce_1` (4 bytes: channel_id LE — uniqueness is what matters), `nonce_2_len = 28`. Frame loop identical in shape to pool's `session.rs` plain-TCP path (6-byte header, accumulate, drain). On connect AND on every declared-job update (watch channel from client loop): send `NewEquihashJob { channel_id, job_id, future_job: false, version, prev_hash, merkle_root, block_commitments, nonce_1, nonce_2_len, time, bits, target: share_target, clean_jobs: true }`. If no declared job yet: send nothing (proxy waits — recon confirmed it reads until first job). Accept only `SUBMIT_EQUIHASH_SHARE` frames; anything else → log + ignore.
- Share intake (`share_path.rs`): for a `SubmitEquihashShare`:
  1. job_id must equal current declared job → else respond `Rejected(StaleJob)`.
  2. Reassemble full 32-byte nonce = channel's `nonce_1` ‖ `nonce_2` (pad/validate length = nonce_2_len).
  3. Build the 140-byte header (same layout as the server; share.time).
  4. Local dedup (HashSet per job, same key recipe as Task 4).
  5. `EquihashValidator::verify_share(header, solution, share_target)` → on failure `Rejected(InvalidSolution)` / `Rejected(LowDifficulty)` as distinguishable (validator's error tells which; if it doesn't distinguish, compare the solution hash against target separately after Equihash structural verify).
  6. Respond `SubmitSharesResponse::Accepted` to the proxy immediately.
  7. Queue the share for upstream relay (mpsc to the client loop); client loop batches queued shares (flush every 2s or 32 shares, whichever first) into `SubmitSharesJd` and logs the response counts.
  8. **Block check:** if the solution hash also meets the block target (`compact_to_target(bits)`), assemble via `block_submitter::build_block_hex(header, solution, coinbase_tx, transactions)`, submit to Zebra, and send `PushSolution` to the pool. Block path failures are logged loudly but do not affect the share response (already accepted).
- Proxy disconnects: drop the session; JD connection untouched. Client-loop reconnects to pool: listener keeps sessions, sends new job when redeclaration succeeds.

Steps:

- [ ] **Step 1 (failing tests, in `listener_tests.rs`, in-process with a raw `TcpStream` acting as the proxy):**
  - `no_job_before_declaration`: connect, assert no frame arrives within 300ms.
  - `job_broadcast_on_declaration`: set state + notify → client receives a well-formed `NewEquihashJob` with `target == share_target` and `clean_jobs`.
  - `stale_job_share_rejected`, `duplicate_share_rejected`, `invalid_solution_rejected`: drive `SubmitEquihashShare` frames, decode `SubmitSharesResponse`, assert reject reasons (these don't need a real solution — invalid ones exercise the paths).
  - `share_path` unit tests for nonce reassembly and the batch/flush logic (pure functions, no sockets).
  - Happy-path accepted-share + relay + block-check: same valid-solution mechanism as Task 4 found; if none is practical, cover acceptance in Task 7's integration test instead and note it in the test file.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement per the contract. **Step 4:** `cargo test -p zcash-jd-client` → PASS; clippy clean.
- [ ] **Step 5:** Commit: `feat(jdc): downstream listener serving declared jobs with local share validation`
- [ ] **Step 6 (separate commit):** wire `--jdc-listen` / env `JDC_LISTEN` (default OFF — `None`; the bundle sets it) into config/main; relay loop into `JdClient::run`. Commit: `feat(jdc): expose downstream listener via JDC_LISTEN`

### Task 6: JDC env vars + policy.toml

**Files:**
- Modify: `crates/zcash-jd-client/src/main.rs` (env attrs: `ZEBRA_RPC`→zebra-url, `POOL_SV2_ENDPOINT`→pool-jd-addr, `ACCOUNT_ID`→user-id, `JDC_LISTEN`, `JDC_POLICY`→policy path)
- Create: `crates/zcash-jd-client/src/policy.rs`
- Test: policy unit tests in `policy.rs`

- [ ] **Step 1 (failing tests):** `policy.rs` tests: absent file → `Ok(None)`; `mode = "include-all"` → `Ok(Some(...))`; `mode = "include-only"` (or any other) → `Err` whose message contains "not yet supported"; `[attestation]` present with include-all → Ok but returns a flag the caller logs as deferred-warning; `[inclusion.preferences]`/`[inclusion.guarantees]` present → Ok with warn flags (these were emitted by old bundles; tolerate + warn, do NOT fail — only the *mode* gates startup).
- [ ] **Step 2:** FAIL. **Step 3:** Implement with `serde`+`toml` (toml is already a workspace dep — verify; add to workspace if not, it's dev-standard). `main.rs`: load at startup, on `Err` exit non-zero with the message; log warnings for deferred sections.
- [ ] **Step 4:** PASS. **Step 5:** Commit: `feat(jdc): env-var config and scoped policy.toml support`

### Task 7: In-process integration test (full chain)

**Files:**
- Create: `crates/zcash-jd-client/tests/tier2_chain_test.rs` (or in zcash-pool-server's tests if dependency direction demands — decide by who can depend on whom; the test needs pool-server, jd-client lib, proxy lib or binary, test-miner lib or binary)

- [ ] **Step 1:** Study `crates/zcash-pool-server/tests/e2e_mining_flow.rs` for the in-process pool + mock template provider pattern, and `zcash-test-miner/src/v1_client.rs` for driving V1.
- [ ] **Step 2:** Write the test: in-process pool (JD enabled, share_target = very easy), in-process JDC (mock Zebra template provider — reuse however e2e_mining_flow mocks `getblocktemplate`; JDC listener on an ephemeral port), proxy and test-miner **spawned as binaries** (test-miner is bin-only — no lib target; spawn `zcash-test-miner --v1 --pool_addr <proxy>` and the proxy binary with `--listen/--upstream`; use `assert_cmd`-style spawning or plain `std::process::Command` with the workspace target dir). Assert within a generous timeout: (a) JDC declared a job (pool's token manager has it), (b) at least one share accepted end-to-end, (c) `payout_tracker` shows credit under the JDC's ACCOUNT_ID, (d) if a block-target solution occurred, submitblock was invoked on the mock (don't require it — CPU luck).
  Real Equihash solving on an easy target should land a share in seconds; mark `#[ignore]` only if it proves >60s in CI, and if so add it to a `just`/`make` target and CI as a separate non-blocking job — do not silently skip.
- [ ] **Step 3:** Make it pass. **Step 4:** Full workspace quartet (build/test/clippy/fmt). **Step 5:** Commit: `test: end-to-end declared-job mining chain (pool+JDC+proxy+V1 miner)`

### Task 8: Dockerfiles + GHCR workflow

**Files:**
- Create: `docker/Dockerfile.job-declarator`, `docker/Dockerfile.translator-proxy`, `.github/workflows/images.yml`, `.dockerignore` (root: `target/`, `.git/`, `docs/`)

- [ ] **Step 1:** Dockerfiles, both same shape (adjust binary/crate names):

```dockerfile
FROM rust:1.87-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p zcash-jd-client

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 sovright
USER sovright
COPY --from=builder /src/target/release/zcash-jd-client /usr/local/bin/job-declarator
ENTRYPOINT ["/usr/local/bin/job-declarator"]
```
(translator-proxy: `-p sovright-v1-stratum-proxy`, binary `sovright-v1-stratum-proxy` → `/usr/local/bin/translator-proxy`. Verify the actual `[[bin]]` names first with `grep -A2 '\[\[bin\]\]' crates/*/Cargo.toml` and check whether the build needs additional apt packages by just building — fix what the build tells you. Pin the rust image to the version CI uses if discoverable, else current stable.)
- [ ] **Step 2:** Local build check of both: `docker build -f docker/Dockerfile.job-declarator -t jd-test .` and the proxy one; then `docker run --rm jd-test --help` → prints clap help including env names.
- [ ] **Step 3:** `images.yml`: on `push: branches: [main]` and `tags: ['v*']`; `permissions: packages: write, contents: read`; matrix over the two images; `docker/metadata-action` for tags (`edge` on main, semver + `latest` on tags); `docker/build-push-action` to `ghcr.io/sovright/job-declarator` / `ghcr.io/sovright/translator-proxy`; login via `GITHUB_TOKEN`.
- [ ] **Step 4:** Validate the workflow YAML (`gh workflow` won't validate offline — `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/images.yml'))"` at minimum).
- [ ] **Step 5:** Commit: `build: Dockerfiles and GHCR publish workflow for the two bundle images`

### Task 9: Product-side bundle realignment

**Files (product worktree, create first: `cd /Users/zakimanian/code/zcash-work/Sovright-Mining-Pool && git worktree add .worktrees/tier2-bundle-images -b feat/tier2-bundle-images origin/main`):**
- Modify: `sovright-api/src/api/bundle.rs` (tier1 + tier2 bodies + tests)

- [ ] **Step 1 (failing tests, extend the existing bundle test module):**
  - tier1 + tier2 reference `ghcr.io/sovright/translator-proxy:v0.1.0`; tier2 references `ghcr.io/sovright/job-declarator:v0.1.0`; no `:latest` for these images anywhere; no `bedrock/` image refs.
  - tier2 proxy env uses `UPSTREAM=jdc:34265`; tier1 proxy env `UPSTREAM=${POOL_SV2_ENDPOINT}`; jdc env block has `ZEBRA_RPC`, `POOL_SV2_ENDPOINT`, `ACCOUNT_ID`, `JDC_LISTEN=0.0.0.0:34265`, `JDC_POLICY=/etc/jdc/policy.toml`.
  - rendered policy.toml contains `mode = "include-all"` and does NOT contain `[attestation]`, `never_filter`, or `signing_key_path`; README contains a roadmap note mentioning attestation as upcoming and does not promise it in present tense.
- [ ] **Step 2:** FAIL. **Step 3:** Implement: rework `render_tier1_body`/`render_tier2_body` env blocks (proxy env: `SV1_LISTEN` + `UPSTREAM`; drop `ACCOUNT_ID` from the proxy services — share attribution rides the V1 username for tier1 and the JDC's `ACCOUNT_ID` for tier2 — and update the READMEs' username instructions accordingly), trim policy.toml to the `[inclusion] mode` section plus a comment block: "preferences, guarantees, and attestation land in a future release; the JDC refuses any mode it cannot enforce." Move the README's guarantee/attestation prose into a "Roadmap" paragraph.
- [ ] **Step 4:** `cargo test -p sovright-api` (run from `sovright-api/`) → PASS. **Step 5:** Commit: `feat(api): bundles reference published ghcr images and real Tier-2 topology`

### Task 10: E2E on the live testnet + release

- [ ] **Step 1:** Push `feat/tier2-images`, open PR to `sovright/mining-infra` main with the full story; get it merged (human gate). Confirm the `images.yml` run on main publishes both `:edge` images; **one-time check** that the sovright org allows the repo's Actions to create packages (Settings → Packages), and after first publish set both GHCR packages to public visibility (manual, org settings).
- [ ] **Step 2:** Tag `v0.1.0` on main → semver images publish.
- [ ] **Step 3:** Update the live pool deploy (sovright-testnet VM): the pool binary must include Tasks 2-4 (new JD messages). Ship archive from the merged main, rebuild `run_pool_testnet`, restart `sovright-pool.service`, confirm `JD Server: enabled` + test-miner shares still flowing (same runbook as the previous workstream's deploy log; remember `sovright-test-miner.service` needs a manual start after pool restarts).
- [ ] **Step 4:** Merge the product PR (Task 9) — note it auto-deploys the internal VM via Cloud Build (env unset there → bundle endpoints inert); then deploy the product stack to the public VM per its archive flow so the live API serves the new bundles.
- [ ] **Step 5:** Real-bundle E2E from the laptop: fetch a Tier-2 bundle from the live API (`ENABLE_TIER_2_BUNDLE=true` locally against the live params — or flip the live flag if the user approves), run the installer, `docker compose up -d`, point a CPU test miner at `localhost:3333`, and verify on the live dashboard: worker visible, shares crediting, and (when lucky) a block submitted by the local Zebra appears in the chain. THIS is the acceptance test for the whole workstream.
- [ ] **Step 6:** Update the deploy log + memory; report what remains for flipping `ENABLE_TIER_2_BUNDLE` publicly (expected: nothing but the flag + run-proxy copy).

## Out of scope (do not build)

Policy preference/guarantee engine; attestation; vardiff on JDC sessions; Noise on the JDC listener; full-template hardening; flipping `ENABLE_TIER_2_BUNDLE` (Step 5 of Task 10 may do it temporarily/locally for testing only, or with explicit user approval).
