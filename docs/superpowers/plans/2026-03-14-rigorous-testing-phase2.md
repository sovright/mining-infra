# Rigorous Testing Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill critical testing gaps before mainnet -- mock Zebra RPC, end-to-end mining flow, concurrent stress tests, error paths for network-facing code, ShareProcessor coverage, benchmarks, and upstream test ports.

**Architecture:** Extract `RpcProvider` trait from `ZebraRpc` with `Box<dyn>` to allow mock injection. Build `TestTemplateFactory` behind a `test-support` feature flag for cross-crate use. Then layer integration tests, stress tests, and benchmarks on top.

**Tech Stack:** Rust, tokio (multi_thread for stress tests), criterion (benchmarks), async-trait, existing proptest/snow/equihash deps.

**Spec:** `docs/superpowers/specs/2026-03-14-rigorous-testing-phase2-design.md`

---

## Task 1: Extract RpcProvider trait and implement for ZebraRpc

**Files:**
- Modify: `crates/zcash-template-provider/src/rpc.rs`
- Modify: `crates/zcash-template-provider/Cargo.toml`

- [ ] **Step 1: Add async-trait dependency**

Add `async-trait = "0.1"` to `[dependencies]` in `crates/zcash-template-provider/Cargo.toml`.

- [ ] **Step 2: Define RpcProvider trait above ZebraRpc**

In `rpc.rs`, add the trait before the `ZebraRpc` struct:

```rust
use async_trait::async_trait;

/// Trait abstracting the Zebra RPC interface for testability
#[async_trait]
pub trait RpcProvider: Send + Sync {
    async fn get_block_template(&self) -> Result<GetBlockTemplateResponse>;
    async fn submit_block(&self, block_hex: &str) -> Result<Option<String>>;
    async fn get_best_block_hash(&self) -> Result<String>;
}
```

- [ ] **Step 3: Implement RpcProvider for ZebraRpc**

Add below the existing `ZebraRpc` impl block:

```rust
#[async_trait]
impl RpcProvider for ZebraRpc {
    async fn get_block_template(&self) -> Result<GetBlockTemplateResponse> {
        self.request("getblocktemplate", serde_json::json!([])).await
    }
    async fn submit_block(&self, block_hex: &str) -> Result<Option<String>> {
        self.request("submitblock", vec![block_hex]).await
    }
    async fn get_best_block_hash(&self) -> Result<String> {
        self.request("getbestblockhash", serde_json::json!([])).await
    }
}
```

Remove the duplicate standalone methods from `ZebraRpc` (lines 76-88) since they're now on the trait.

- [ ] **Step 4: Export the trait from lib.rs**

Add `pub use rpc::RpcProvider;` to `crates/zcash-template-provider/src/lib.rs`.

- [ ] **Step 5: Run tests**

Run: `cargo test -p zcash-template-provider`
Expected: All existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/zcash-template-provider/
git commit -m "refactor: extract RpcProvider trait from ZebraRpc"
```

---

## Task 2: Make TemplateProvider use Box<dyn RpcProvider>

**Files:**
- Modify: `crates/zcash-template-provider/src/template.rs`

- [ ] **Step 1: Change rpc field to trait object**

In `template.rs`, change the `TemplateProvider` struct:

```rust
use crate::rpc::RpcProvider;  // add this import

pub struct TemplateProvider {
    config: TemplateProviderConfig,
    rpc: Box<dyn RpcProvider>,  // was: ZebraRpc
    // ... rest unchanged
}
```

- [ ] **Step 2: Update constructor to box ZebraRpc**

In `TemplateProvider::new()`, change:
```rust
rpc: Box::new(rpc),  // was: rpc,
```

- [ ] **Step 3: Add constructor for custom RPC provider**

Add a new method:
```rust
/// Create with a custom RPC provider (for testing)
pub fn with_rpc(config: TemplateProviderConfig, rpc: Box<dyn RpcProvider>) -> Self {
    let (sender, _) = broadcast::channel(16);
    Self {
        config,
        rpc,
        template_id: AtomicU64::new(1),
        current_template: Arc::new(RwLock::new(None)),
        sender,
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p zcash-template-provider && cargo test -p zcash-pool-server`
Expected: All tests pass (no public API change).

- [ ] **Step 5: Commit**

```bash
git add crates/zcash-template-provider/src/template.rs
git commit -m "refactor: make TemplateProvider generic over RpcProvider via Box<dyn>"
```

---

## Task 3: Create MockZebraRpc and TestTemplateFactory

**Files:**
- Create: `crates/zcash-template-provider/src/testutil.rs`
- Modify: `crates/zcash-template-provider/src/lib.rs`
- Modify: `crates/zcash-template-provider/Cargo.toml`

- [ ] **Step 1: Add test-support feature to Cargo.toml**

In `crates/zcash-template-provider/Cargo.toml`, add:
```toml
[features]
test-support = []
```

- [ ] **Step 2: Gate testutil module in lib.rs**

Add to `crates/zcash-template-provider/src/lib.rs`:
```rust
#[cfg(any(test, feature = "test-support"))]
pub mod testutil;
```

- [ ] **Step 3: Create testutil.rs**

Create `crates/zcash-template-provider/src/testutil.rs`:

```rust
//! Test utilities: mock RPC provider and template factory.
//!
//! Gated behind the `test-support` feature for cross-crate use.

use crate::error::Result;
use crate::rpc::RpcProvider;
use crate::types::{
    BlockTemplate, DefaultRoots, GetBlockTemplateResponse, TemplateTransaction,
};
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::Mutex;

/// Mock Zebra RPC that returns pre-built responses from a queue.
pub struct MockZebraRpc {
    templates: Mutex<VecDeque<Result<GetBlockTemplateResponse>>>,
    submitted_blocks: Mutex<Vec<String>>,
}

impl MockZebraRpc {
    pub fn new() -> Self {
        Self {
            templates: Mutex::new(VecDeque::new()),
            submitted_blocks: Mutex::new(Vec::new()),
        }
    }

    /// Queue a successful template response
    pub fn enqueue_template(&self, response: GetBlockTemplateResponse) {
        self.templates.lock().unwrap().push_back(Ok(response));
    }

    /// Queue an error response
    pub fn enqueue_error(&self, err: crate::error::Error) {
        self.templates.lock().unwrap().push_back(Err(err));
    }

    /// Get blocks that were submitted via submit_block
    pub fn submitted_blocks(&self) -> Vec<String> {
        self.submitted_blocks.lock().unwrap().clone()
    }
}

#[async_trait]
impl RpcProvider for MockZebraRpc {
    async fn get_block_template(&self) -> Result<GetBlockTemplateResponse> {
        self.templates
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(crate::error::Error::Rpc("no more mock templates".into())))
    }

    async fn submit_block(&self, block_hex: &str) -> Result<Option<String>> {
        self.submitted_blocks.lock().unwrap().push(block_hex.to_string());
        Ok(None)
    }

    async fn get_best_block_hash(&self) -> Result<String> {
        Ok("0".repeat(64))
    }
}

/// Builder for valid GetBlockTemplateResponse values.
///
/// Produces templates with valid EquihashHeader serialization (140 bytes).
pub struct TestTemplateFactory {
    height: u64,
    prev_hash: String,
    version: u32,
    time: u64,
    bits: String,
    target: String,
    transactions: Vec<TemplateTransaction>,
    coinbase_hex: String,
}

impl Default for TestTemplateFactory {
    fn default() -> Self {
        Self {
            height: 1_000_000,
            prev_hash: "0".repeat(64),
            version: 5,
            time: 1_700_000_000,
            bits: "2007ffff".to_string(),
            target: "0".repeat(64),
            transactions: vec![],
            // Minimal valid coinbase (just enough to not be empty)
            coinbase_hex: "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000".to_string(),
        }
    }
}

impl TestTemplateFactory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn height(mut self, h: u64) -> Self {
        self.height = h;
        self
    }

    pub fn prev_hash(mut self, h: &str) -> Self {
        self.prev_hash = h.to_string();
        self
    }

    pub fn time(mut self, t: u64) -> Self {
        self.time = t;
        self
    }

    pub fn with_transactions(mut self, txs: Vec<TemplateTransaction>) -> Self {
        self.transactions = txs;
        self
    }

    pub fn build(self) -> GetBlockTemplateResponse {
        GetBlockTemplateResponse {
            version: self.version,
            previous_block_hash: self.prev_hash,
            default_roots: DefaultRoots {
                merkle_root: "0".repeat(64),
                chain_history_root: "0".repeat(64),
                auth_data_root: "0".repeat(64),
                block_commitments_hash: "0".repeat(64),
            },
            transactions: self.transactions,
            coinbase_txn: serde_json::json!({ "data": self.coinbase_hex }),
            target: self.target,
            height: self.height,
            bits: self.bits,
            cur_time: self.time,
        }
    }
}
```

- [ ] **Step 4: Write a test for the factory**

Add to the bottom of `testutil.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::assemble_header;

    #[test]
    fn factory_produces_valid_header() {
        let response = TestTemplateFactory::new().build();
        let header = assemble_header(&response).unwrap();
        let bytes = header.serialize();
        assert_eq!(bytes.len(), 140);
    }

    #[test]
    fn factory_builder_methods() {
        let response = TestTemplateFactory::new()
            .height(500_000)
            .time(1_800_000_000)
            .build();
        assert_eq!(response.height, 500_000);
        assert_eq!(response.cur_time, 1_800_000_000);
    }

    #[tokio::test]
    async fn mock_rpc_returns_queued_templates() {
        let mock = MockZebraRpc::new();
        mock.enqueue_template(TestTemplateFactory::new().build());

        let result = mock.get_block_template().await;
        assert!(result.is_ok());

        // Second call should error (queue empty)
        let result = mock.get_block_template().await;
        assert!(result.is_err());
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p zcash-template-provider`
Expected: All pass including new testutil tests.

- [ ] **Step 6: Commit**

```bash
git add crates/zcash-template-provider/
git commit -m "feat: add MockZebraRpc and TestTemplateFactory behind test-support feature"
```

---

## Task 4: ShareProcessor deeper coverage (Spec Section 6)

**Files:**
- Modify: `crates/zcash-pool-server/src/share.rs`

- [ ] **Step 1: Add tests for validate_share via Channel**

Read `crates/zcash-pool-server/src/share.rs` and `crates/zcash-pool-server/src/channel.rs` to understand the `validate_share()` method that takes a `Channel`. Add these tests to the existing `mod tests`:

**Test 1:** Share for unknown job -> `PoolError::UnknownJob(999)`
**Test 2:** Share for stale job (add job, then add_job with clean_jobs=true, submit to stale) -> `RejectReason::StaleJob`
**Test 3:** Share with wrong nonce_2 length (e.g., 10 bytes when job expects 28) -> `PoolError::InvalidMessage`
**Test 4:** Duplicate through Channel path -- submit twice, first gets InvalidSolution, second gets Duplicate
**Test 5:** Timestamp boundary acceptance -- `job_time - 60` and `job_time + 7200` both pass time check (not rejected for timestamp)

- [ ] **Step 2: Run tests**

Run: `cargo test -p zcash-pool-server -- share::tests`
Expected: All pass.

- [ ] **Step 3: Commit**

```bash
git add crates/zcash-pool-server/src/share.rs
git commit -m "test: add ShareProcessor tests for job lookup, staleness, nonce length, and boundaries"
```

---

## Task 5: Noise handshake error paths (Spec Section 5)

**Files:**
- Modify: `crates/bedrock-noise/src/handshake.rs`

- [ ] **Step 1: Add error path tests**

Read `crates/bedrock-noise/src/handshake.rs` (existing test module at line 134). Add 3 new tests:

**Test 1: `test_wrong_server_public_key`** -- Client uses `Keypair::generate().public` (different from server's actual key). Handshake should error.

**Test 2: `test_server_drops_mid_handshake`** -- Server accepts TCP then immediately drops the stream (drop the TcpStream). Client's `connect()` should return an IO error.

**Test 3: `test_garbage_data_handshake`** -- Instead of a real client, write random bytes to the server's accepted stream. Server's `accept()` should return an error.

All use the existing pattern: `TcpListener::bind("127.0.0.1:0")`, spawn server task, client connects.

- [ ] **Step 2: Run tests**

Run: `cargo test -p bedrock-noise -- handshake::tests`
Expected: All 4 tests pass (1 existing + 3 new).

- [ ] **Step 3: Commit**

```bash
git add crates/bedrock-noise/src/handshake.rs
git commit -m "test: add Noise handshake error path tests (wrong key, drop, garbage)"
```

---

## Task 6: Concurrent stress tests (Spec Section 3)

**Files:**
- Create: `crates/zcash-pool-server/tests/concurrent_stress.rs`

- [ ] **Step 1: Write concurrent stress tests**

Create `crates/zcash-pool-server/tests/concurrent_stress.rs` with 4 tests. All use `#[tokio::test(flavor = "multi_thread")]` because the types use `std::sync::RwLock`.

**Test 1: `test_payout_tracker_concurrent_writes`**
- Create `Arc<PayoutTracker>`, spawn 50 tasks via `tokio::spawn`
- Each task records 1000 shares with difficulty 1.0 for a unique miner ID
- Use `Arc<tokio::sync::Barrier>` with 50 parties to synchronize start
- After all tasks complete (join all handles), verify:
  - `get_all_stats().len() == 50`
  - Each miner has total_shares == 1000, total_difficulty == 1000.0

**Test 2: `test_duplicate_detector_toctou`**
- Create `Arc<InMemoryDuplicateDetector>`
- Spawn 100 tasks that all call `check_and_record(1, &same_nonce, &same_solution)` simultaneously (barrier sync)
- Collect results: count how many returned `false` (not duplicate)
- Assert exactly 1 returned `false`, 99 returned `true`

**Test 3: `test_job_distributor_concurrent_access`**
- Wrap `JobDistributor` in `Arc<tokio::sync::RwLock<JobDistributor>>`
- 1 writer task updates templates 100 times with incrementing heights
- 20 reader tasks repeatedly acquire read lock and call `create_job()`
- All tasks complete without panics

**Test 4: `test_channel_concurrent_job_cleanup`**
- Wrap `Channel` in `Arc<tokio::sync::RwLock<Channel>>`
- 1 writer task adds 100 jobs with `clean_jobs=true`
- 1 reader task calls `is_job_active()` in a loop
- Both complete without panics

- [ ] **Step 2: Run tests**

Run: `cargo test -p zcash-pool-server --test concurrent_stress`
Expected: All 4 pass.

- [ ] **Step 3: Commit**

```bash
git add crates/zcash-pool-server/tests/concurrent_stress.rs
git commit -m "test: add concurrent stress tests for PayoutTracker, DuplicateDetector, JobDistributor"
```

---

## Task 7: End-to-end mining flow (Spec Section 2)

**Files:**
- Create: `crates/zcash-pool-server/tests/e2e_mining_flow.rs`
- Modify: `crates/zcash-pool-server/Cargo.toml`

- [ ] **Step 1: Add test-support feature dep**

Add to `[dev-dependencies]` in `crates/zcash-pool-server/Cargo.toml`:
```toml
zcash-template-provider = { path = "../zcash-template-provider", features = ["test-support"] }
```

(This may already be there without the feature -- just add the feature.)

- [ ] **Step 2: Write E2E test**

Create `crates/zcash-pool-server/tests/e2e_mining_flow.rs`:

This test exercises: template -> job -> share -> validation -> payout -> vardiff -> new block.

```rust
//! End-to-end mining flow integration test.
//!
//! Tests the full pipeline: template -> job -> share -> validation -> payout
//! without a network or real Zebra node.

use std::time::Duration;
use zcash_equihash_validator::VardiffConfig;
use zcash_mining_protocol::messages::{NewEquihashJob, ShareResult, RejectReason, SubmitEquihashShare};
use zcash_pool_server::{
    Channel, InMemoryDuplicateDetector, DuplicateDetector, JobDistributor, PayoutTracker,
    ShareProcessor,
};
use zcash_template_provider::testutil::TestTemplateFactory;
use zcash_template_provider::header::assemble_header;
use zcash_template_provider::types::{BlockTemplate, Hash256};
```

Then write a single `#[test] fn test_full_mining_lifecycle()` that:

1. Creates a template via `TestTemplateFactory`, processes it through `assemble_header` to get a `BlockTemplate`
2. Feeds it to `JobDistributor::update_template()` -- assert returns `true` (new block)
3. Creates a `Channel` with 4-byte nonce_1, gets a job via `distributor.create_job(&channel, true)`
4. Builds a `SubmitEquihashShare` with `time == job.time`, 28-byte nonce_2, dummy 1344-byte solution
5. Validates via `ShareProcessor::validate_share_with_job()` -- expect rejection for InvalidSolution (not panic)
6. Submits same share again -- expect Duplicate rejection
7. Records shares in `PayoutTracker`, verifies accumulation
8. Creates `VardiffController`, records shares, calls `maybe_retarget()`
9. Creates second template with different prev_hash, feeds to distributor -- assert `true` (new block)
10. Old job should be stale after `channel.add_job(new_job, true)`

- [ ] **Step 3: Run test**

Run: `cargo test -p zcash-pool-server --test e2e_mining_flow`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/zcash-pool-server/tests/e2e_mining_flow.rs crates/zcash-pool-server/Cargo.toml
git commit -m "test: add end-to-end mining flow integration test"
```

---

## Task 8: ForgeRelay error path tests (Spec Section 4)

**Files:**
- Modify: `crates/zcash-pool-server/src/forge.rs`

- [ ] **Step 1: Refactor builder logic into free functions**

Read `crates/zcash-pool-server/src/forge.rs`. Extract `build_compact_block_from_template` and `compute_header_hash` as `pub(crate)` free functions that take explicit parameters instead of `&self`:

```rust
pub(crate) fn compute_header_hash(header: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let first = Sha256::digest(header);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

pub(crate) fn build_compact_block(template: &BlockTemplate, nonce: u64) -> Result<CompactBlock> {
    // ... move the body of build_compact_block_from_template here
}
```

Update `ForgeRelay` methods to call these free functions.

- [ ] **Step 2: Add tests**

Add `#[cfg(test)] mod tests` to `forge.rs`:

**Test 1:** `ForgeRelay::new()` with empty peers -> error containing "cannot be empty"

**Test 2:** `build_compact_block()` with valid template from `TestTemplateFactory` -> verify header length is 1487, coinbase prefilled at index 0, correct number of short IDs

**Test 3:** Template with non-hex tx hash -> that tx is skipped, block still builds

**Test 4:** `compute_header_hash()` with known input matches `bedrock_forge::CompactBlock::header_hash()` for the same header bytes

- [ ] **Step 3: Run tests**

Run: `cargo test -p zcash-pool-server -- forge::tests`
Expected: All pass.

- [ ] **Step 4: Commit**

```bash
git add crates/zcash-pool-server/src/forge.rs
git commit -m "test: add ForgeRelay error path tests, refactor builder to free functions"
```

---

## Task 9: Benchmarks (Spec Section 7)

**Files:**
- Create: `crates/zcash-pool-server/benches/share_bench.rs`
- Create: `crates/zcash-pool-server/benches/payout_bench.rs`
- Create: `crates/zcash-pool-common/benches/compact_size_bench.rs`
- Create: `crates/bedrock-noise/benches/transport_bench.rs`
- Modify: `crates/zcash-pool-server/Cargo.toml`
- Modify: `crates/zcash-pool-common/Cargo.toml`
- Modify: `crates/bedrock-noise/Cargo.toml`

- [ ] **Step 1: Add criterion deps and bench entries**

For each crate, add to Cargo.toml:

```toml
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }

[[bench]]
name = "<bench_name>"
harness = false
```

- [ ] **Step 2: Write share_bench.rs**

Benchmark `ShareProcessor::validate_share_with_job()` with dummy solutions. Measure the overhead before Equihash validation rejects.

- [ ] **Step 3: Write payout_bench.rs**

Benchmark `PayoutTracker::record_share()` single-threaded throughput.

- [ ] **Step 4: Write compact_size_bench.rs**

Benchmark `write_compact_size()` + `read_compact_size()` roundtrip for values across all encoding ranges (1-byte, 3-byte, 5-byte, 9-byte).

- [ ] **Step 5: Write transport_bench.rs**

Benchmark Noise `write_message()` + `read_message()` roundtrip for 100-byte and 10KB payloads over localhost.

- [ ] **Step 6: Run benchmarks**

Run: `cargo bench -p zcash-pool-server -- --quick`
Run: `cargo bench -p zcash-pool-common -- --quick`
Run: `cargo bench -p bedrock-noise -- --quick`
Expected: All run and produce timing output.

- [ ] **Step 7: Commit**

```bash
git add crates/zcash-pool-server/benches/ crates/zcash-pool-server/Cargo.toml \
       crates/zcash-pool-common/benches/ crates/zcash-pool-common/Cargo.toml \
       crates/bedrock-noise/benches/ crates/bedrock-noise/Cargo.toml
git commit -m "bench: add criterion benchmarks for share validation, payout, CompactSize, Noise"
```

---

## Task 10: BIP 152 compact block compatibility tests (Spec Section 8, tests 1-6)

**Files:**
- Create: `crates/bedrock-forge/tests/bip152_compat.rs`

- [ ] **Step 1: Read upstream test patterns**

Read Bitcoin Core's `blockencodings_tests.cpp` approach and our `bedrock-forge/src/reconstructor.rs`, `bedrock-forge/src/builder.rs`, `bedrock-forge/src/compact_block.rs` to understand our compact block API.

- [ ] **Step 2: Write BIP 152 compatibility tests**

Create `crates/bedrock-forge/tests/bip152_compat.rs`:

**Test 1: `simple_roundtrip`** -- Build a compact block with 1 coinbase + 2 mempool txs. Receiver has both txs in mempool. Reconstruct -> Complete.

**Test 2: `empty_block_roundtrip`** -- Coinbase-only block. No short IDs. Reconstructs with just prefilled.

**Test 3: `reconstruction_with_missing_tx`** -- Receiver missing 1 tx. Result is Incomplete with correct `unresolved_short_ids`.

**Test 4: `short_id_key_derivation`** -- For a known header hash and nonce, compute `ShortId::compute()` and verify k0/k1 derivation: k0 = header_hash[0..8] as LE u64, k1 = header_hash[8..16] XOR nonce.

**Test 5: `prefilled_index_overflow`** -- Prefilled tx with index beyond total tx count -> Invalid result.

- [ ] **Step 3: Run tests**

Run: `cargo test -p bedrock-forge --test bip152_compat`
Expected: All pass.

- [ ] **Step 4: Commit**

```bash
git add crates/bedrock-forge/tests/bip152_compat.rs
git commit -m "test: add BIP 152 compact block compatibility tests"
```

---

## Task 11: Noise NK test vectors (Spec Section 8, test 9)

**Files:**
- Create: `crates/bedrock-noise/tests/noise_test_vectors.rs`

- [ ] **Step 1: Research test vectors**

Fetch cacophony test vectors for `Noise_NK_25519_ChaChaPoly_BLAKE2s` from `github.com/noiseprotocol/noise_wiki/wiki/Test-vectors`. Extract the relevant vector (initiator ephemeral key, responder static key, handshake messages, payloads).

- [ ] **Step 2: Write test vector validation**

Create `crates/bedrock-noise/tests/noise_test_vectors.rs`:

Use `snow::Builder` directly with known keys to verify our handshake implementation produces the expected ciphertext bytes for each handshake step. This validates interoperability with any Noise NK implementation.

If exact test vectors aren't available for our specific variant, write a deterministic handshake test with fixed keys that verifies:
- Handshake messages are the expected length
- Transport mode produces consistent ciphertext for known plaintext
- Both sides derive the same transport keys

- [ ] **Step 3: Run tests**

Run: `cargo test -p bedrock-noise --test noise_test_vectors`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/bedrock-noise/tests/noise_test_vectors.rs
git commit -m "test: add Noise NK handshake test vector validation"
```

---

## Task 12: Double-roundtrip fuzz pattern (Spec Section 8, test 8)

**Files:**
- Modify: fuzz targets in `crates/zcash-mining-protocol/fuzz/`

- [ ] **Step 1: Read existing fuzz targets**

Read the fuzz targets in `crates/zcash-mining-protocol/fuzz/fuzz_targets/` to understand the current pattern.

- [ ] **Step 2: Update to double-roundtrip**

For each roundtrip fuzz target, update the pattern from:
```
bytes -> decode -> encode -> compare
```
to:
```
bytes -> decode -> encode -> re-decode -> re-encode -> compare encoded bytes
```

This matches SRI's `test_roundtrip!` macro and catches bugs where the first decode succeeds but produces a value that doesn't re-encode identically.

- [ ] **Step 3: Run fuzz targets briefly**

Run each updated target for 10 seconds to verify no immediate failures:
```bash
cargo fuzz run <target> -- -max_total_time=10
```

- [ ] **Step 4: Commit**

```bash
git add crates/zcash-mining-protocol/fuzz/
git commit -m "test: adopt double-roundtrip fuzz pattern from SRI"
```
