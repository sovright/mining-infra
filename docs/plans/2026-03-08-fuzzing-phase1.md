# Fuzzing Phase 1: Mining Protocol Parser Fuzzing

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add cargo-fuzz targets to `zcash-mining-protocol` to find crashes, panics, and roundtrip correctness bugs in all network-facing parsers.

**Architecture:** Per-crate `fuzz/` directory using `cargo-fuzz` (libFuzzer). 5 raw-byte targets exercise each decoder with arbitrary bytes. 4 structured roundtrip targets use `#[derive(Arbitrary)]` to verify encode/decode symmetry. Seed corpus extracted from existing tests. CI runs corpus regression on every PR.

**Tech Stack:** `cargo-fuzz`, `libfuzzer-sys`, `arbitrary` crate with derive feature.

---

### Task 1: Add `arbitrary` as optional dependency

**Files:**
- Modify: `crates/zcash-mining-protocol/Cargo.toml`

**Step 1: Add the dependency**

In `crates/zcash-mining-protocol/Cargo.toml`, add `arbitrary` as an optional dependency:

```toml
[dependencies]
serde.workspace = true
thiserror.workspace = true
byteorder.workspace = true
arbitrary = { version = "1", features = ["derive"], optional = true }
```

**Step 2: Verify it compiles**

Run: `cargo check -p zcash-mining-protocol`
Expected: compiles without errors, `arbitrary` not pulled in by default.

Run: `cargo check -p zcash-mining-protocol --features arbitrary`
Expected: compiles with arbitrary enabled.

**Step 3: Commit**

```bash
git add crates/zcash-mining-protocol/Cargo.toml
git commit -m "Add optional arbitrary dependency to zcash-mining-protocol for fuzzing"
```

---

### Task 2: Derive `Arbitrary` on message types

**Files:**
- Modify: `crates/zcash-mining-protocol/src/messages.rs`

**Step 1: Add conditional derives to all 5 types**

Add `#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]` to each type. The types and their locations:

On `NewEquihashJob` (line 21, before `pub struct`):
```rust
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct NewEquihashJob {
```

On `SubmitEquihashShare` (line 89):
```rust
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SubmitEquihashShare {
```

On `SubmitSharesResponse` (line 120):
```rust
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SubmitSharesResponse {
```

On `ShareResult` (line 131):
```rust
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ShareResult {
```

On `RejectReason` (line 140):
```rust
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum RejectReason {
```

On `SetTarget` (line 155):
```rust
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SetTarget {
```

**Step 2: Verify it compiles with and without the feature**

Run: `cargo check -p zcash-mining-protocol`
Expected: compiles (arbitrary not active, derive is conditional).

Run: `cargo check -p zcash-mining-protocol --features arbitrary`
Expected: compiles with Arbitrary derived on all types.

Run: `cargo test -p zcash-mining-protocol`
Expected: all existing tests pass.

**Step 3: Commit**

```bash
git add crates/zcash-mining-protocol/src/messages.rs
git commit -m "Derive Arbitrary on mining protocol message types behind feature flag"
```

---

### Task 3: Initialize cargo-fuzz and create raw byte targets

**Files:**
- Create: `crates/zcash-mining-protocol/fuzz/Cargo.toml`
- Create: `crates/zcash-mining-protocol/fuzz/fuzz_targets/fuzz_frame_decode.rs`
- Create: `crates/zcash-mining-protocol/fuzz/fuzz_targets/fuzz_decode_new_job.rs`
- Create: `crates/zcash-mining-protocol/fuzz/fuzz_targets/fuzz_decode_submit_share.rs`
- Create: `crates/zcash-mining-protocol/fuzz/fuzz_targets/fuzz_decode_submit_response.rs`
- Create: `crates/zcash-mining-protocol/fuzz/fuzz_targets/fuzz_decode_set_target.rs`

**Step 1: Initialize cargo-fuzz**

Run from workspace root:
```bash
cd crates/zcash-mining-protocol && cargo fuzz init
```

This creates `fuzz/Cargo.toml` and `fuzz/fuzz_targets/`. Delete the auto-generated example target if one is created.

**Step 2: Edit `fuzz/Cargo.toml`**

Replace the generated content with:

```toml
[package]
name = "zcash-mining-protocol-fuzz"
version = "0.0.0"
publish = false
edition = "2021"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
arbitrary = { version = "1", features = ["derive"] }
zcash-mining-protocol = { path = "..", features = ["arbitrary"] }

[[bin]]
name = "fuzz_frame_decode"
path = "fuzz_targets/fuzz_frame_decode.rs"
doc = false

[[bin]]
name = "fuzz_decode_new_job"
path = "fuzz_targets/fuzz_decode_new_job.rs"
doc = false

[[bin]]
name = "fuzz_decode_submit_share"
path = "fuzz_targets/fuzz_decode_submit_share.rs"
doc = false

[[bin]]
name = "fuzz_decode_submit_response"
path = "fuzz_targets/fuzz_decode_submit_response.rs"
doc = false

[[bin]]
name = "fuzz_decode_set_target"
path = "fuzz_targets/fuzz_decode_set_target.rs"
doc = false

# Roundtrip targets (Task 4)
[[bin]]
name = "fuzz_roundtrip_new_job"
path = "fuzz_targets/fuzz_roundtrip_new_job.rs"
doc = false

[[bin]]
name = "fuzz_roundtrip_submit_share"
path = "fuzz_targets/fuzz_roundtrip_submit_share.rs"
doc = false

[[bin]]
name = "fuzz_roundtrip_submit_response"
path = "fuzz_targets/fuzz_roundtrip_submit_response.rs"
doc = false

[[bin]]
name = "fuzz_roundtrip_set_target"
path = "fuzz_targets/fuzz_roundtrip_set_target.rs"
doc = false
```

**Step 3: Create `fuzz_frame_decode.rs`**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_mining_protocol::codec::MessageFrame;

fuzz_target!(|data: &[u8]| {
    let _ = MessageFrame::decode(data);
});
```

**Step 4: Create `fuzz_decode_new_job.rs`**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_mining_protocol::codec::decode_new_equihash_job;

fuzz_target!(|data: &[u8]| {
    let _ = decode_new_equihash_job(data);
});
```

**Step 5: Create `fuzz_decode_submit_share.rs`**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_mining_protocol::codec::decode_submit_share;

fuzz_target!(|data: &[u8]| {
    let _ = decode_submit_share(data);
});
```

**Step 6: Create `fuzz_decode_submit_response.rs`**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_mining_protocol::codec::decode_submit_shares_response;

fuzz_target!(|data: &[u8]| {
    let _ = decode_submit_shares_response(data);
});
```

**Step 7: Create `fuzz_decode_set_target.rs`**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_mining_protocol::codec::decode_set_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_set_target(data);
});
```

**Step 8: Verify all targets build**

Run: `cd crates/zcash-mining-protocol && cargo +nightly fuzz build`
Expected: all 5 raw byte targets compile (roundtrip targets will fail until Task 4).

Note: if roundtrip target files don't exist yet, cargo fuzz build will fail. Either create empty placeholder files or temporarily comment out the roundtrip `[[bin]]` entries in `fuzz/Cargo.toml` and re-add them in Task 4.

**Step 9: Commit**

```bash
git add crates/zcash-mining-protocol/fuzz/
git commit -m "Add raw byte fuzz targets for all mining protocol decoders"
```

---

### Task 4: Create structured roundtrip targets

**Files:**
- Create: `crates/zcash-mining-protocol/fuzz/fuzz_targets/fuzz_roundtrip_new_job.rs`
- Create: `crates/zcash-mining-protocol/fuzz/fuzz_targets/fuzz_roundtrip_submit_share.rs`
- Create: `crates/zcash-mining-protocol/fuzz/fuzz_targets/fuzz_roundtrip_submit_response.rs`
- Create: `crates/zcash-mining-protocol/fuzz/fuzz_targets/fuzz_roundtrip_set_target.rs`

**Step 1: Create `fuzz_roundtrip_new_job.rs`**

The roundtrip target generates a random `NewEquihashJob` via `Arbitrary`, but must constrain `nonce_1.len() + nonce_2_len == 32` since the encoder doesn't enforce this but the decoder does. We fix nonce lengths post-generation.

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use zcash_mining_protocol::codec::{encode_new_equihash_job, decode_new_equihash_job};
use zcash_mining_protocol::messages::NewEquihashJob;

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(mut job) = NewEquihashJob::arbitrary(&mut u) else { return };

    // Constrain: nonce_1.len() + nonce_2_len must == 32
    if job.nonce_1.len() > 32 {
        job.nonce_1.truncate(32);
    }
    job.nonce_2_len = (32 - job.nonce_1.len()) as u8;

    let encoded = match encode_new_equihash_job(&job) {
        Ok(e) => e,
        Err(_) => return,
    };
    let decoded = decode_new_equihash_job(&encoded)
        .expect("decode must succeed for encoder output");

    assert_eq!(job, decoded, "roundtrip mismatch");
});
```

**Step 2: Create `fuzz_roundtrip_submit_share.rs`**

The encoder casts `nonce_2.len()` to `u8`, so constrain length to 0..=32.

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use zcash_mining_protocol::codec::{encode_submit_share, decode_submit_share};
use zcash_mining_protocol::messages::SubmitEquihashShare;

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(mut share) = SubmitEquihashShare::arbitrary(&mut u) else { return };

    // Constrain nonce_2 to valid range
    if share.nonce_2.len() > 32 {
        share.nonce_2.truncate(32);
    }

    let encoded = match encode_submit_share(&share) {
        Ok(e) => e,
        Err(_) => return,
    };
    let decoded = decode_submit_share(&encoded)
        .expect("decode must succeed for encoder output");

    assert_eq!(share, decoded, "roundtrip mismatch");
});
```

**Step 3: Create `fuzz_roundtrip_submit_response.rs`**

The `Other` reject reason message is truncated to 255 bytes by the encoder, so truncate before comparing.

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use zcash_mining_protocol::codec::{encode_submit_shares_response, decode_submit_shares_response};
use zcash_mining_protocol::messages::{SubmitSharesResponse, ShareResult, RejectReason};

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(mut resp) = SubmitSharesResponse::arbitrary(&mut u) else { return };

    // The encoder truncates Other messages to 255 bytes.
    // Normalize before roundtrip comparison.
    if let ShareResult::Rejected(RejectReason::Other(ref mut msg)) = resp.result {
        // Encoder writes msg.as_bytes()[..min(len,255)], so truncate at byte boundary
        let max = 255;
        if msg.len() > max {
            // Truncate to valid UTF-8 boundary at or before 255 bytes
            let truncated = &msg.as_bytes()[..max];
            match std::str::from_utf8(truncated) {
                Ok(s) => *msg = s.to_string(),
                Err(e) => *msg = std::str::from_utf8(&truncated[..e.valid_up_to()])
                    .unwrap()
                    .to_string(),
            }
        }
    }

    let encoded = match encode_submit_shares_response(&resp) {
        Ok(e) => e,
        Err(_) => return,
    };
    let decoded = decode_submit_shares_response(&encoded)
        .expect("decode must succeed for encoder output");

    assert_eq!(resp, decoded, "roundtrip mismatch");
});
```

**Step 4: Create `fuzz_roundtrip_set_target.rs`**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use zcash_mining_protocol::codec::{encode_set_target, decode_set_target};
use zcash_mining_protocol::messages::SetTarget;

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(msg) = SetTarget::arbitrary(&mut u) else { return };

    let encoded = match encode_set_target(&msg) {
        Ok(e) => e,
        Err(_) => return,
    };
    let decoded = decode_set_target(&encoded)
        .expect("decode must succeed for encoder output");

    assert_eq!(msg, decoded, "roundtrip mismatch");
});
```

**Step 5: Verify all 9 targets build**

Run: `cd crates/zcash-mining-protocol && cargo +nightly fuzz build`
Expected: all 9 targets compile successfully.

**Step 6: Commit**

```bash
git add crates/zcash-mining-protocol/fuzz/fuzz_targets/
git commit -m "Add structured roundtrip fuzz targets for mining protocol messages"
```

---

### Task 5: Seed corpus from existing tests

**Files:**
- Create: `crates/zcash-mining-protocol/fuzz/corpus/` directories and seed files

**Step 1: Create a seed corpus generator test**

Create a temporary test that writes encoded messages to files. Add to `crates/zcash-mining-protocol/tests/generate_corpus.rs`:

```rust
//! One-shot test to generate seed corpus files for fuzzing.
//! Run: cargo test -p zcash-mining-protocol --test generate_corpus -- --ignored

use zcash_mining_protocol::codec::*;
use zcash_mining_protocol::messages::*;
use std::fs;

#[test]
#[ignore]
fn generate_fuzz_corpus() {
    let corpus_base = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus");

    // Frame decode corpus
    let dir = format!("{}/fuzz_frame_decode", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let frame = MessageFrame { extension_type: 0, msg_type: 0x20, length: 100 };
    fs::write(format!("{}/valid_frame", dir), frame.encode()).unwrap();
    fs::write(format!("{}/empty", dir), &[]).unwrap();
    fs::write(format!("{}/short", dir), &[0x00, 0x00]).unwrap();

    // NewEquihashJob corpus
    let dir = format!("{}/fuzz_decode_new_job", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let job = NewEquihashJob {
        channel_id: 1, job_id: 42, future_job: false, version: 5,
        prev_hash: [0xaa; 32], merkle_root: [0xbb; 32], block_commitments: [0xcc; 32],
        nonce_1: vec![0x01, 0x02, 0x03, 0x04], nonce_2_len: 28,
        time: 1700000000, bits: 0x1d00ffff, target: [0x00; 32], clean_jobs: true,
    };
    fs::write(format!("{}/valid_job", dir), encode_new_equihash_job(&job).unwrap()).unwrap();

    // SubmitEquihashShare corpus
    let dir = format!("{}/fuzz_decode_submit_share", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let share = SubmitEquihashShare {
        channel_id: 1, sequence_number: 100, job_id: 42,
        nonce_2: vec![0xff; 28], time: 1700000001, solution: [0x12; 1344],
    };
    fs::write(format!("{}/valid_share", dir), encode_submit_share(&share).unwrap()).unwrap();

    // SubmitSharesResponse corpus
    let dir = format!("{}/fuzz_decode_submit_response", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let accepted = SubmitSharesResponse {
        channel_id: 42, sequence_number: 100, result: ShareResult::Accepted,
    };
    fs::write(format!("{}/accepted", dir), encode_submit_shares_response(&accepted).unwrap()).unwrap();
    let rejected = SubmitSharesResponse {
        channel_id: 1, sequence_number: 5,
        result: ShareResult::Rejected(RejectReason::StaleJob),
    };
    fs::write(format!("{}/rejected_stale", dir), encode_submit_shares_response(&rejected).unwrap()).unwrap();
    let other = SubmitSharesResponse {
        channel_id: 3, sequence_number: 77,
        result: ShareResult::Rejected(RejectReason::Other("custom error".to_string())),
    };
    fs::write(format!("{}/rejected_other", dir), encode_submit_shares_response(&other).unwrap()).unwrap();

    // SetTarget corpus
    let dir = format!("{}/fuzz_decode_set_target", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let target = SetTarget { channel_id: 99, target: [0xab; 32] };
    fs::write(format!("{}/valid_target", dir), encode_set_target(&target).unwrap()).unwrap();

    // Roundtrip targets share the same corpus as their decode counterparts
    // (libfuzzer will use these as seeds, then mutate via Arbitrary)
    for (src, dst) in [
        ("fuzz_decode_new_job", "fuzz_roundtrip_new_job"),
        ("fuzz_decode_submit_share", "fuzz_roundtrip_submit_share"),
        ("fuzz_decode_submit_response", "fuzz_roundtrip_submit_response"),
        ("fuzz_decode_set_target", "fuzz_roundtrip_set_target"),
    ] {
        let src_dir = format!("{}/{}", corpus_base, src);
        let dst_dir = format!("{}/{}", corpus_base, dst);
        fs::create_dir_all(&dst_dir).unwrap();
        for entry in fs::read_dir(&src_dir).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), format!("{}/{}", dst_dir, entry.file_name().to_str().unwrap())).unwrap();
        }
    }

    println!("Corpus files generated in {}", corpus_base);
}
```

**Step 2: Run the generator**

Run: `cargo test -p zcash-mining-protocol --test generate_corpus -- --ignored`
Expected: corpus files created under `fuzz/corpus/`.

**Step 3: Verify corpus files exist**

Run: `find crates/zcash-mining-protocol/fuzz/corpus -type f | wc -l`
Expected: ~15 files across 9 directories.

**Step 4: Add .gitignore for artifacts and target**

Create `crates/zcash-mining-protocol/fuzz/.gitignore`:

```
target/
artifacts/
```

**Step 5: Commit**

```bash
git add crates/zcash-mining-protocol/fuzz/corpus/
git add crates/zcash-mining-protocol/fuzz/.gitignore
git add crates/zcash-mining-protocol/tests/generate_corpus.rs
git commit -m "Add seed corpus for mining protocol fuzz targets"
```

---

### Task 6: Smoke test all fuzz targets

**Step 1: Run each raw byte target for 10 seconds**

Run each from `crates/zcash-mining-protocol/`:

```bash
cargo +nightly fuzz run fuzz_frame_decode -- -max_total_time=10
cargo +nightly fuzz run fuzz_decode_new_job -- -max_total_time=10
cargo +nightly fuzz run fuzz_decode_submit_share -- -max_total_time=10
cargo +nightly fuzz run fuzz_decode_submit_response -- -max_total_time=10
cargo +nightly fuzz run fuzz_decode_set_target -- -max_total_time=10
```

Expected: each completes without crashes. Output shows coverage metrics and `Done N runs`.

**Step 2: Run each roundtrip target for 10 seconds**

```bash
cargo +nightly fuzz run fuzz_roundtrip_new_job -- -max_total_time=10
cargo +nightly fuzz run fuzz_roundtrip_submit_share -- -max_total_time=10
cargo +nightly fuzz run fuzz_roundtrip_submit_response -- -max_total_time=10
cargo +nightly fuzz run fuzz_roundtrip_set_target -- -max_total_time=10
```

Expected: each completes without crashes or assertion failures.

**Step 3: If any target crashes, fix the bug**

If a crash is found:
1. The crash input is saved in `fuzz/artifacts/<target>/`
2. Reproduce with: `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>`
3. Fix the bug in `codec.rs` or `messages.rs`
4. Add the crash input to `fuzz/corpus/<target>/` as a regression test
5. Commit the fix and updated corpus

**Step 4: Update corpus with any new coverage**

After the smoke runs, the fuzzer will have expanded the corpus. Check in the new corpus entries:

```bash
git add crates/zcash-mining-protocol/fuzz/corpus/
git commit -m "Update fuzz corpus after initial smoke runs"
```

---

### Task 7: Add CI corpus regression workflow

**Files:**
- Create: `.github/workflows/fuzz-regression.yml`

**Step 1: Create the workflow**

```yaml
name: Fuzz Regression

on:
  pull_request:
  push:
    branches: [main]

jobs:
  fuzz-regression:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        target:
          - fuzz_frame_decode
          - fuzz_decode_new_job
          - fuzz_decode_submit_share
          - fuzz_decode_submit_response
          - fuzz_decode_set_target
          - fuzz_roundtrip_new_job
          - fuzz_roundtrip_submit_share
          - fuzz_roundtrip_submit_response
          - fuzz_roundtrip_set_target
    steps:
      - uses: actions/checkout@v4

      - name: Install nightly toolchain
        uses: dtolnay/rust-toolchain@nightly

      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz --locked

      - name: Cache fuzz build
        uses: actions/cache@v4
        with:
          path: crates/zcash-mining-protocol/fuzz/target
          key: fuzz-${{ matrix.target }}-${{ hashFiles('crates/zcash-mining-protocol/**/*.rs') }}

      - name: Run corpus regression
        working-directory: crates/zcash-mining-protocol
        run: cargo +nightly fuzz run ${{ matrix.target }} -- -runs=0
```

**Step 2: Verify the workflow syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/fuzz-regression.yml'))"`

Or if `python3` with yaml is unavailable:
Run: `cat .github/workflows/fuzz-regression.yml`
Manually verify YAML indentation is correct.

**Step 3: Commit**

```bash
mkdir -p .github/workflows
git add .github/workflows/fuzz-regression.yml
git commit -m "Add CI workflow for fuzz corpus regression testing"
```

---

### Task 8: Final verification

**Step 1: Verify everything builds from clean state**

Run from workspace root:
```bash
cargo check -p zcash-mining-protocol
cargo check -p zcash-mining-protocol --features arbitrary
cargo test -p zcash-mining-protocol
```

Expected: all pass.

**Step 2: Verify fuzz targets build**

Run:
```bash
cd crates/zcash-mining-protocol && cargo +nightly fuzz build
```

Expected: 9 targets compile.

**Step 3: Verify corpus regression**

Run:
```bash
cd crates/zcash-mining-protocol && cargo +nightly fuzz run fuzz_frame_decode -- -runs=0
```

Expected: runs through all corpus entries and exits cleanly.

---

## Summary

| Task | What | Files |
|------|------|-------|
| 1 | Add `arbitrary` optional dep | `Cargo.toml` |
| 2 | Derive `Arbitrary` on message types | `messages.rs` |
| 3 | Init cargo-fuzz, create 5 raw byte targets | `fuzz/` directory |
| 4 | Create 4 structured roundtrip targets | `fuzz/fuzz_targets/` |
| 5 | Generate seed corpus from existing tests | `fuzz/corpus/`, `tests/generate_corpus.rs` |
| 6 | Smoke test all 9 targets | (no new files) |
| 7 | CI corpus regression workflow | `.github/workflows/fuzz-regression.yml` |
| 8 | Final verification | (no new files) |

## Phase 2 (future)

After Phase 1 is stable:
- Add fuzz targets for `bedrock-forge` chunk parsers
- Add fuzz targets for `zcash-jd-server` codec
- Stateful session fuzzing with sequences of messages
- OSS-Fuzz integration for continuous cloud fuzzing
- Nightly CI runs with longer time budgets
