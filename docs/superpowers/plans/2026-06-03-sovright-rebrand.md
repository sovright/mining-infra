# Sovright Rebrand Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebrand the repository from Bedrock/Forge to Sovright (Zcash Mining Pool and Relay Network) — crate renames, identifier renames, doc updates, and GitHub repo rename — with no compatibility shims.

**Architecture:** Pure mechanical rename in dependency order (leaf crates first, then the pool server that depends on them, then docs, then GitHub). Each task leaves the workspace compiling and tests passing, verified by `cargo check`/`cargo test` and committed before moving on.

**Tech Stack:** Rust workspace (cargo), `git mv`, `perl -pi -e` for in-place edits (portable on macOS — do NOT use bare `sed -i`), `gh api` for the repo rename.

**Spec:** `docs/superpowers/specs/2026-06-03-sovright-rebrand-design.md`

---

## Global Rename Table (reference for all tasks)

| Old | New |
|---|---|
| `bedrock-noise` / `bedrock_noise` | `sovright-noise` / `sovright_noise` |
| `bedrock-strata` / `bedrock_strata` | `sovright-telemetry` / `sovright_telemetry` |
| `bedrock-forge` / `bedrock_forge` | `sovright-relay` / `sovright_relay` |
| `forge-sidecar` / `forge_sidecar` | `sovright-relay-sidecar` / `sovright_relay_sidecar` (binary: `relay-sidecar`) |
| `bedrock-v1-proxy` / `bedrock_v1_proxy` | `sovright-v1-stratum-proxy` / `sovright_v1_stratum_proxy` |
| `bedrock_pool_` (metric prefix) | `sovright_pool_` |
| `ForgeRelay` (type) | `RelayClient` |
| `ForgeMissingAuthKey` (error variant) | `RelayMissingAuthKey` |
| config keys `forge_relay_enabled`, `forge_relay_peers`, `forge_bind_addr`, `forge_auth_key`, `forge_data_shards`, `forge_parity_shards` | `relay_enabled`, `relay_peers`, `relay_bind_addr`, `relay_auth_key`, `relay_data_shards`, `relay_parity_shards` |
| Cargo feature `forge` (`zcash-pool-server`) | feature `relay` — **must rename `Cargo.toml` and ALL `#[cfg(feature = "forge")]` sites together** (see Task 6 Step 2b) |
| "FORGE" / "Forge" (prose: comments, log messages, docs) | "relay network" / "relay" (use judgment for grammar) |
| "Bedrock" (prose) | "Sovright" |
| "Strata" (prose, in telemetry crate) | "Telemetry" |

Additional functional renames (user-approved decisions):

| Old | New |
|---|---|
| `network_name = "BedrockTestnet"` (testnet config) | `network_name = "SovrightTestnet"` — **breaking: existing internal-testnet nodes must be redeployed together** |
| `b"/Bedrock/"` coinbase tag (`zcash-coinbase`) | `b"/Sovright/"` (update test assertions alongside) |
| `testnet/zebrad-bedrock-bootstrap.toml` (filename) | `testnet/zebrad-sovright-bootstrap.toml` |

**Out of scope — do NOT touch:** `docs/plans/*`, `docs/superpowers/plans/*` (except this file's checkboxes), `docs/superpowers/specs/*`, `crates/*/docs/plans/*` (these move with `git mv` of their crate directory but contents stay unchanged), `.claude/` (third-party skill files). `noise_*` config keys are unchanged. `origin` remote is unchanged.

**The canonical grep gate** — use this exact snippet wherever a task says "run the grep gate". Exclusions: historical docs, `.claude/`, build/git dirs, and legitimate English words containing "forge" ("forgery", "forgetting"):

```bash
grep -rin -E 'bedrock|forge' . \
  --include='*.rs' --include='*.toml' --include='*.md' \
  | grep -v -E 'docs/plans/|docs/superpowers/|target/|\.git/|\.claude/' \
  | grep -viE 'forger|forgett?ing'
```

Expected when done: empty output. (Note `crates/sovright-relay/docs/*.md` — but NOT its `docs/plans/` — are living docs and get rebranded, so they must pass the gate too.)

**Note on fuzz lockfiles:** `crates/*/fuzz/Cargo.lock` files retain stale `bedrock-*` package entries after renaming. They are excluded from the gate (no `--include` match) and don't affect the main build, but regenerate them if convenient: `cd crates/<crate>/fuzz && cargo update -w` (or delete the lockfiles and let the next fuzz run regenerate).

---

### Task 0: Baseline check

- [ ] **Step 1: Verify clean tree and passing build**

Run: `git status --short && cargo check 2>&1 | tail -3`
Expected: empty status, `Finished` line with no errors. If the baseline is broken, stop and surface to the user.

---

### Task 1: Rename `bedrock-noise` → `sovright-noise`

**Files:**
- Move: `crates/bedrock-noise/` → `crates/sovright-noise/`
- Modify: its `Cargo.toml`, every `Cargo.toml` depending on it, every `.rs` file with `bedrock_noise` imports, `crates/sovright-noise/README.md`

- [ ] **Step 1: Move the directory**

```bash
git mv crates/bedrock-noise crates/sovright-noise
```

- [ ] **Step 2: Rename package and all references (code + manifests)**

```bash
grep -rl -E 'bedrock[-_]noise' --include='*.rs' --include='*.toml' crates/ \
  | xargs perl -pi -e 's/bedrock-noise/sovright-noise/g; s/bedrock_noise/sovright_noise/g'
```

- [ ] **Step 3: Rebrand prose in the crate (description, README, doc comments)**

In `crates/sovright-noise/Cargo.toml`: description → `"Noise Protocol encryption for Sovright mining infrastructure"`. In `crates/sovright-noise/README.md` and `src/*.rs` comments, replace "Bedrock" → "Sovright". Check with:

```bash
grep -rin -E 'bedrock|forge' crates/sovright-noise/
```

Expected: zero hits.

- [ ] **Step 4: Verify build**

Run: `cargo check 2>&1 | tail -3`
Expected: `Finished`, no errors.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: rename bedrock-noise to sovright-noise"
```

---

### Task 2: Rename `bedrock-strata` → `sovright-telemetry`

**Files:**
- Move: `crates/bedrock-strata/` → `crates/sovright-telemetry/`
- Modify: its `Cargo.toml`, dependent `Cargo.toml`s, `.rs` files importing `bedrock_strata`, metric name strings in `src/metrics.rs`, `README.md`

- [ ] **Step 1: Move the directory**

```bash
git mv crates/bedrock-strata crates/sovright-telemetry
```

- [ ] **Step 2: Rename package and all code references**

```bash
grep -rl -E 'bedrock[-_]strata' --include='*.rs' --include='*.toml' crates/ \
  | xargs perl -pi -e 's/bedrock-strata/sovright-telemetry/g; s/bedrock_strata/sovright_telemetry/g'
```

Note: this also fixes doc-comment examples like `use bedrock_strata::...` — verify none remain afterward.

- [ ] **Step 3: Rename metric prefix `bedrock_pool_` → `sovright_pool_`**

```bash
grep -rl 'bedrock_pool_' --include='*.rs' crates/ \
  | xargs perl -pi -e 's/bedrock_pool_/sovright_pool_/g'
```

- [ ] **Step 4: Rebrand prose**

`Cargo.toml` description → `"Telemetry: monitoring and analytics layer for Sovright mining infrastructure"`. In `README.md` and source comments, "Strata" → "Telemetry", "Bedrock" → "Sovright". Check:

```bash
grep -rin -E 'bedrock|strata|forge' crates/sovright-telemetry/
```

Expected: zero hits.

- [ ] **Step 5: Verify build and crate tests**

Run: `cargo test -p sovright-telemetry 2>&1 | tail -5`
Expected: all tests pass (metric-name assertions now check `sovright_pool_*`).

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "refactor: rename bedrock-strata to sovright-telemetry, metrics prefix to sovright_pool_"
```

---

### Task 3: Rename `bedrock-forge` → `sovright-relay`

**Files:**
- Move: `crates/bedrock-forge/` → `crates/sovright-relay/`
- Modify: its `Cargo.toml` (and `fuzz/Cargo.toml` if present), dependent `Cargo.toml`s, `.rs` files importing `bedrock_forge`, prose in `README.md`/comments. Its `docs/plans/*` move with the directory but contents are NOT edited.

- [ ] **Step 1: Move the directory**

```bash
git mv crates/bedrock-forge crates/sovright-relay
```

- [ ] **Step 2: Rename package and all code references (including fuzz targets, benches, tests)**

```bash
grep -rl -E 'bedrock[-_]forge' --include='*.rs' --include='*.toml' crates/ \
  | xargs perl -pi -e 's/bedrock-forge/sovright-relay/g; s/bedrock_forge/sovright_relay/g'
```

- [ ] **Step 3: Rebrand prose in the crate (NOT docs/plans/)**

`Cargo.toml` description → `"Fast block relay protocol for the Sovright Zcash mining network"`. In `README.md`, `src/**/*.rs`, `tests/**/*.rs`, `benches/`, `fuzz/`, and the living docs `docs/testing.md` and `docs/fibre-zcash-planning.md`: "FORGE" → "the relay protocol" / "relay" (grammar permitting), "Bedrock" → "Sovright". Do NOT edit `crates/sovright-relay/docs/plans/*`. Check:

```bash
grep -rin -E 'bedrock|forge' crates/sovright-relay/ | grep -v docs/plans
```

Expected: zero hits.

- [ ] **Step 4: Verify build and crate tests**

Run: `cargo test -p sovright-relay 2>&1 | tail -5`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: rename bedrock-forge to sovright-relay"
```

---

### Task 4: Rename `forge-sidecar` → `sovright-relay-sidecar`

**Files:**
- Move: `crates/forge-sidecar/` → `crates/sovright-relay-sidecar/`
- Modify: its `Cargo.toml` (package name, `[[bin]]` name → `relay-sidecar`, `[lib]` name → `sovright_relay_sidecar`), `.rs` files, `README.md`, dependent manifests

- [ ] **Step 1: Move the directory**

```bash
git mv crates/forge-sidecar crates/sovright-relay-sidecar
```

- [ ] **Step 2: Rename package, lib, and code references**

```bash
grep -rl -E 'forge[-_]sidecar' --include='*.rs' --include='*.toml' --include='*.md' crates/ \
  | xargs perl -pi -e 's/forge-sidecar/sovright-relay-sidecar/g; s/forge_sidecar/sovright_relay_sidecar/g'
```

Then in `crates/sovright-relay-sidecar/Cargo.toml`, set the binary name explicitly:

```toml
[[bin]]
name = "relay-sidecar"
path = "src/main.rs"
```

(The blanket rename will have set it to `sovright-relay-sidecar`; shorten the bin name to `relay-sidecar` per spec.)

- [ ] **Step 3: Rebrand remaining prose and identifiers in the crate**

`Cargo.toml` description → `"Relay sidecar for Stratum V1 mining pools (part of the Sovright network)"`. In `src/*.rs`, `README.md`, and `config.example.toml`: remaining `Forge*` types per the global table, `forge_*` config keys → `relay_*` per the global table, `forge-relay.example.com` → `relay.example.com`, "FORGE" → "relay", "Bedrock" → "Sovright". Check:

```bash
grep -rin -E 'bedrock|forge' crates/sovright-relay-sidecar/
```

Expected: zero hits.

- [ ] **Step 4: Verify build and binary name**

Run: `cargo build -p sovright-relay-sidecar 2>&1 | tail -3 && ls target/debug/relay-sidecar`
Expected: build succeeds, binary `target/debug/relay-sidecar` exists.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: rename forge-sidecar to sovright-relay-sidecar (binary: relay-sidecar)"
```

---

### Task 5: Rename `bedrock-v1-proxy` → `sovright-v1-stratum-proxy`

**Files:**
- Move: `crates/bedrock-v1-proxy/` → `crates/sovright-v1-stratum-proxy/`
- Modify: its `Cargo.toml`, `.rs` files, dependent manifests, any `[[bin]]` name

- [ ] **Step 1: Move the directory**

```bash
git mv crates/bedrock-v1-proxy crates/sovright-v1-stratum-proxy
```

- [ ] **Step 2: Rename package and code references**

```bash
grep -rl -E 'bedrock[-_]v1[-_]proxy' --include='*.rs' --include='*.toml' --include='*.md' crates/ \
  | xargs perl -pi -e 's/bedrock-v1-proxy/sovright-v1-stratum-proxy/g; s/bedrock_v1_proxy/sovright_v1_stratum_proxy/g'
```

- [ ] **Step 3: Rebrand prose**

`Cargo.toml` description → `"Stratum V1 translation proxy for the Sovright Zcash mining pool"`. Replace remaining "Bedrock"/"forge" prose in `src/*.rs` (e.g. `session.rs` has several). Check:

```bash
grep -rin -E 'bedrock|forge' crates/sovright-v1-stratum-proxy/
```

Expected: zero hits.

- [ ] **Step 4: Verify build and crate tests**

Run: `cargo test -p sovright-v1-stratum-proxy 2>&1 | tail -5`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: rename bedrock-v1-proxy to sovright-v1-stratum-proxy"
```

---

### Task 6: Pool server — Forge → Relay (module, types, config keys)

**Files:**
- Rename: `crates/zcash-pool-server/src/forge.rs` → `relay.rs`
- Rename: `crates/zcash-pool-server/tests/forge_integration_test.rs` → `relay_integration_test.rs`
- Modify: `crates/zcash-pool-server/src/lib.rs`, `src/server.rs`, `src/config.rs`, `examples/run_pool.rs`

- [ ] **Step 1: Rename files**

```bash
git mv crates/zcash-pool-server/src/forge.rs crates/zcash-pool-server/src/relay.rs
git mv crates/zcash-pool-server/tests/forge_integration_test.rs crates/zcash-pool-server/tests/relay_integration_test.rs
```

- [ ] **Step 2: Rename types, module, and config keys across the workspace**

```bash
grep -rl -E 'ForgeRelay|ForgeMissingAuthKey|forge_relay_enabled|forge_relay_peers|forge_bind_addr|forge_auth_key|forge_data_shards|forge_parity_shards|\bforge\b' \
  --include='*.rs' crates/ \
  | xargs perl -pi -e '
      s/ForgeRelay/RelayClient/g;
      s/ForgeMissingAuthKey/RelayMissingAuthKey/g;
      s/forge_relay_enabled/relay_enabled/g;
      s/forge_relay_peers/relay_peers/g;
      s/forge_bind_addr/relay_bind_addr/g;
      s/forge_auth_key/relay_auth_key/g;
      s/forge_data_shards/relay_data_shards/g;
      s/forge_parity_shards/relay_parity_shards/g;
      s/\bmod forge\b/mod relay/g;
      s/\bforge::/relay::/g;
      s/forge_relay/relay/g;
    '
```

- [ ] **Step 2b: Rename the Cargo `forge` feature → `relay` (DANGER: silent-miscompile risk)**

`crates/zcash-pool-server/Cargo.toml` defines `default = ["forge"]` and `forge = ["dep:bedrock-forge"]` (the dep name will already say `sovright-relay` after Task 3). There are 11 `#[cfg(feature = "forge")]` / `#[cfg(not(feature = "forge"))]` sites across `src/lib.rs`, `src/server.rs`, and the integration test. **If the feature is renamed in `Cargo.toml` but any cfg site is missed, that code is silently compiled out with no error.** Rename both together:

```bash
perl -pi -e 's/^forge = \[/relay = [/; s/default = \["forge"\]/default = ["relay"]/' crates/zcash-pool-server/Cargo.toml
grep -rl 'feature = "forge"' --include='*.rs' crates/ | xargs perl -pi -e 's/feature = "forge"/feature = "relay"/g'
```

Verify no cfg site was missed and both feature configurations compile:

```bash
grep -rn 'feature = "forge"' crates/   # expected: zero hits
cargo build -p zcash-pool-server 2>&1 | tail -2
cargo build -p zcash-pool-server --no-default-features 2>&1 | tail -2
```

Also confirm the relay module is actually present in the default build (not silently cfg'd out):

```bash
grep -n 'mod relay' crates/zcash-pool-server/src/lib.rs
```

- [ ] **Step 3: Fix remaining `forge` identifiers and prose by hand**

Sweep what the regex missed (test fn names like `forge_zero_data_shards_rejected` → `relay_zero_data_shards_rejected`, local vars, log messages, comments, error display strings such as `"forge_relay_enabled requires forge_auth_key"` → `"relay_enabled requires relay_auth_key"`):

```bash
grep -rin -E 'bedrock|forge' \
  crates/zcash-pool-server/ crates/zcash-jd-server/ crates/zcash-jd-client/ crates/zcash-test-miner/ \
  | grep -viE 'forger|forgett?ing'
```

Fix every hit. Expected after fixes: zero hits. Do NOT touch `crates/zcash-jd-server/src/token.rs`'s "token forgery" comment — "forgery" is legitimate English, hence the carve-out.

- [ ] **Step 3b: Rename the coinbase tag in `zcash-coinbase`**

In `crates/zcash-coinbase/src/builder.rs`: `b"/Bedrock/"` → `b"/Sovright/"`, and update the test assertions on the tag in the same file. Note `/Sovright/` is one byte longer than `/Bedrock/` — check any length-sensitive assertions. Verify:

```bash
grep -rin -E 'bedrock|forge' crates/zcash-coinbase/ && cargo test -p zcash-coinbase 2>&1 | tail -3
```

Expected: zero grep hits, tests pass.

- [ ] **Step 4: Verify full workspace build and tests**

Run: `cargo test 2>&1 | tail -10`
Expected: all tests pass across the workspace.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: rename Forge relay to relay in pool server (RelayClient, relay_* config keys)"
```

---

### Task 6b: Testnet configs and Dockerfiles

**Files:**
- Rename: `testnet/zebrad-bedrock-bootstrap.toml` → `testnet/zebrad-sovright-bootstrap.toml`
- Modify: that file, `testnet/zebrad.toml`, `testnet/deployments.md`, `testnet/Dockerfile`, `testnet/Dockerfile.test-miner`

- [ ] **Step 1: Rename the bootstrap config file**

```bash
git mv testnet/zebrad-bedrock-bootstrap.toml testnet/zebrad-sovright-bootstrap.toml
```

- [ ] **Step 2: Rename the network identifier and rebrand testnet files**

In `testnet/zebrad-sovright-bootstrap.toml` (and `testnet/zebrad.toml` if present there): `network_name = "BedrockTestnet"` → `network_name = "SovrightTestnet"`. **Breaking:** existing internal-testnet nodes must be redeployed together — note this in `deployment.md` (Task 8). Rebrand remaining Bedrock/Forge references (crate names, binary names, prose) in `testnet/zebrad.toml` (has a "Bedrock Internal Testnet" comment), `testnet/deployments.md`, `testnet/Dockerfile`, `testnet/Dockerfile.test-miner` — including the old `forge-sidecar` binary path → `relay-sidecar` and any reference to the renamed bootstrap filename.

- [ ] **Step 3: Verify**

```bash
grep -rin -E 'bedrock|forge' testnet/
```

Expected: zero hits.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "refactor: rename testnet network to SovrightTestnet, rebrand testnet configs"
```

---

### Task 7: Workspace manifest and final code sweep

**Files:**
- Modify: `Cargo.toml` (workspace root), any straggler files

- [ ] **Step 1: Update workspace repository field**

In root `Cargo.toml`: `repository = "https://github.com/sovright/mining-infra"`. Also update any per-crate `repository` overrides (e.g. `crates/sovright-relay/Cargo.toml` has one) to the same URL.

- [ ] **Step 2: Run the canonical grep gate restricted to code**

Run the canonical grep gate (see header) but with only `--include='*.rs' --include='*.toml'`.
Expected: zero hits. Fix any stragglers.

- [ ] **Step 3: Full verification**

Run: `cargo build --release 2>&1 | tail -3 && cargo test 2>&1 | tail -5 && cargo clippy 2>&1 | tail -5`
Expected: build finishes, all tests pass, clippy clean (no new warnings vs. baseline).

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "refactor: update workspace repository URL, finish code rebrand sweep"
```

---

### Task 8: Living docs rebrand

**Files:**
- Modify: `README.md`, `CLAUDE.md`, `deployment.md`, `docs/integration/pool-operator-guide.md`, `docs/integration/mining-software-integration.md`, `docs/integration/migration-from-v1.md`, `docs/security/stratum-v2-attack-analysis.md`, crate `README.md`s if any references remain

- [ ] **Step 1: README.md**

New title: `# Sovright — Zcash Mining Pool and Relay Network`. Replace all Bedrock/Forge references; update crate names in any tables/diagrams to the new names.

- [ ] **Step 2: CLAUDE.md**

Update: project overview, crate dependency graph (new crate names), key files table (`forge.rs` → `relay.rs`), config field list (`forge_relay_*` → `relay_*`), and any other Bedrock/Forge mentions.

- [ ] **Step 3: deployment.md**

Rename crate/binary/config references, and add a prominent **Breaking changes** note: (a) config keys `forge_*` → `relay_*` with the full old→new key table, (b) Prometheus metrics `bedrock_pool_*` → `sovright_pool_*` (dashboards/alerts must be updated), (c) binary `forge-sidecar` → `relay-sidecar`.

- [ ] **Step 4: docs/integration/* and docs/security/***

Replace Bedrock/Forge references in `pool-operator-guide.md`, `mining-software-integration.md`, `migration-from-v1.md`, and `docs/security/stratum-v2-attack-analysis.md` (crate names, config keys, binary names, prose).

- [ ] **Step 5: Grep gate on living docs**

```bash
grep -rin -E 'bedrock|forge' README.md CLAUDE.md deployment.md docs/integration/ docs/security/ crates/*/README.md \
  | grep -viE 'forger|forgett?ing'
```

Expected: zero hits.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "docs: rebrand living documentation to Sovright"
```

---

### Task 9: GitHub repo rename and remote update

**Outward-facing — confirm with the user immediately before executing this task.**

- [ ] **Step 1: Rename the GitHub repo**

```bash
gh api -X PATCH repos/sovright/bedrock -f name=mining-infra
```

Expected: JSON response with `"full_name": "sovright/mining-infra"`. GitHub auto-redirects the old URL.

- [ ] **Step 2: Update the local remote**

```bash
git remote rename bedrock sovright
git remote set-url sovright https://github.com/sovright/mining-infra.git
git remote -v
```

Expected: `sovright  https://github.com/sovright/mining-infra.git` (fetch/push); `origin` unchanged.

- [ ] **Step 3: Verify connectivity**

Run: `git ls-remote sovright HEAD`
Expected: returns a commit hash without error.

---

### Task 10: Final verification

- [ ] **Step 1: Full grep gate**

Run the canonical grep gate from the plan header verbatim.
Expected: empty output. (Remaining `bedrock`/`forge` hits live only in `docs/plans/`, `docs/superpowers/`, `crates/sovright-relay/docs/plans/`, and `.claude/` — all excluded by the gate.)

- [ ] **Step 2: Full build, test, clippy**

Run: `cargo build --release 2>&1 | tail -3 && cargo test 2>&1 | tail -5 && cargo clippy --all-targets 2>&1 | tail -5`
Expected: all clean.

- [ ] **Step 3: Report**

Summarize to the user: commits made, breaking changes (config keys, metric names, binary name), new repo URL.
