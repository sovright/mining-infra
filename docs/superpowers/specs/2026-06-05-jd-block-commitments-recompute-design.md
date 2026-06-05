# JD Block-Commitments Recompute — Design

Date: 2026-06-05
Status: Approved by Zaki (this session); spec review pending
Repo: `sovright/mining-infra`, branch `feat/jd-block-commitments`
Predecessor: the Tier-2 functional-core + images workstream (`2026-06-04-tier2-functional-core-images-design.md`, merged). Its live E2E surfaced this bug.

## Problem

In Job Declaration coinbase-only mode, the JDC (`crates/zcash-jd-client`):
1. fetches a block template from its **own** zebra (whose template coinbase pays the bundle's `[mining] miner_address`),
2. rebuilds the coinbase from the **pool's** `coinbase_output` (delivered in `AllocateMiningJobTokenSuccess`), and recomputes `merkle_root`,
3. but declares `block_commitments` **copied verbatim** from its own zebra's template header (`template_builder.rs:133` — `template.header.hash_block_commitments.0`).

That copied value was derived from a *different* coinbase than the one the JDC actually builds. The pool then rejects the declaration with "block commitments do not match current template" (`server.rs:233`).

**Confirmed on the live testnet:** the two templates share an identical `chainhistoryroot` (`daea4add…`) but differ in `authdataroot` (`b61c0e…` vs `e2343c…`) purely because their coinbases differ, so `blockcommitmentshash = f(chainhistoryroot, authdataroot)` differs. The chains are not forked (block hashes through the tip are identical).

Two facts make the fix span both the JDC and the pool:
- **The eventual block uses the JDC's coinbase.** Its header `block_commitments` must equal `hashBlockCommitments(chainHistoryRoot, authDataRoot([jdc_coinbase, …txs]))`, or it fails at `submitblock`. So the JDC must *recompute*, not copy.
- **The pool's expected value is wrong.** `validate_header_fields` (`server.rs:219-249`) compares the declared `block_commitments` to its own template's — built with the pool zebra's coinbase (a *different* address than the JD `coinbase_output` the JDC uses). It already does **not** check `merkle_root` (it accepts the custom-coinbase merkle root), so rejecting the custom-coinbase `block_commitments` is internally inconsistent. The pool must validate by recomputation instead.

Why earlier tests missed it: the in-process integration test (`tier2_chain_test.rs`) used a *single* zebra for both the pool's template provider and the JDC, so both sides held identical coinbases and commitments. Only the live E2E, with two independent zebras using different miner addresses, exposed it.

## Decisions (with Zaki)

1. **Pool validation: recompute & verify.** The pool stores the chain-history root + branch id, recomputes the expected `block_commitments` from the **declared** coinbase + txs, and verifies the JDC's value. Preserves the pool's role (reject invalid templates before miners waste work); reuses the pool-side `zcash-coinbase` crate.
2. **Consensus branch id source: zebra `getblockchaininfo`.** Zebra's `getblocktemplate` does **not** carry a branch id (verified: response keys lack it). `getblockchaininfo` returns `consensus.nextblock` (the branch id for the block being mined; `c8e71055` on this NU6 chain). This honors the "from zebra, upgrade-safe, no hardcoded activation table" intent.
3. **Scope: coinbase-only now; full-template deferred.** *(Revised during spec review — supersedes the earlier "both modes" intent.)* The coinbase-only path (`client.rs:502`) is the actual live bug and is fully supported by existing primitives. Full-template (`client.rs:613`) shares the copy-bug but its fix requires computing ZIP-244 auth digests for arbitrary **non-coinbase** transactions (potentially shielded Sapling/Orchard) — `zcash-coinbase` only implements the coinbase sentinel case, so this is substantial net-new crypto, not "more txs in the same loop." Full-template is `--full-template`-gated and off in the bundle. This spec fixes coinbase-only and leaves the full-template `block_commitments` copy in place behind its flag, with an explicit deferral note in code so it isn't silently shipped as correct.

## Architecture

Reuses existing primitives — no new crypto for the coinbase-only fix this spec covers (full-template's general auth-digest computation is the deferred piece, per Scope decision 3):

| Function | Crate | Purpose |
|---|---|---|
| `compute_coinbase_auth_digest(script_sigs, branch_id) -> [u8;32]` | `zcash-coinbase/src/auth_digest.rs` | auth digest of the constructed coinbase |
| `compute_auth_data_root(&[[u8;32]]) -> [u8;32]` | `zcash-coinbase/src/auth_digest.rs` | merkle root over tx auth digests (coinbase-only = the single digest) |
| `calculate_block_commitments_hash(&Hash256, &Hash256) -> Hash256` | `zcash-template-provider/src/commitments.rs` | `hashBlockCommitments` (wrap the `[u8;32]` roots in `Hash256`) |

### JDC side (`zcash-template-provider`, `zcash-jd-client`)

- **Template provider** threads two net-new zebra-sourced fields into `BlockTemplate` (neither exists there today):
  - `chain_history_root: [u8;32]` from `getblocktemplate` `defaultroots.chainhistoryroot` (the field exists in `DefaultRoots`; thread it onto `BlockTemplate`).
  - `consensus_branch_id: u32` from a new `getblockchaininfo` call (`consensus.nextblock`, hex → u32) via the existing `rpc.rs::request(method, params)` client. Branch id changes only at upgrade boundaries; cache it and refresh on height change.
- **`template_builder`**: replace `block_commitments(&self, template)` with a recompute that takes the constructed coinbase bytes + the template's other-tx auth digests:
  - extract the coinbase's transparent `script_sig` from the JDC-built coinbase via `zcash-coinbase/src/tx_parse.rs::parse_transaction()` (`ParsedTx` → `TxIn.script_sig`),
  - `coinbase_digest = compute_coinbase_auth_digest(script_sigs, template.consensus_branch_id)`,
  - `auth_data_root = compute_auth_data_root(&[coinbase_digest, ...other_tx_digests])`,
  - `block_commitments = calculate_block_commitments_hash(template.chain_history_root, auth_data_root)`.
- **`client.rs`**: `handle_coinbase_only_job` calls the recompute instead of reading `template.header.hash_block_commitments`. `handle_full_template_job` keeps copying for now (behind `--full-template`) with a `TODO`/deferral comment naming this spec, because correct full-template recompute needs general non-coinbase auth digests (see Scope decision 3). For coinbase-only, `other_tx_digests` is empty, so `auth_data_root` = the coinbase digest.
- **Failure handling:** if the chain-history root or branch id is unavailable, the JDC fails the declaration with a clear error and does not declare — never ship a guessed commitment.

### Pool side (`zcash-jd-server`, reuses `zcash-coinbase`)

- **`CurrentTemplateContext`** (`server.rs:96`) gains `chain_history_root: [u8;32]` and `consensus_branch_id: u32`, populated each template cycle from the pool's own template provider + `getblockchaininfo`.
- **`validate_header_fields`**: replace `if block_commitments != template.block_commitments` with recompute-and-verify:
  - from the **declared** `coinbase_tx` (in `SetCustomMiningJob`), compute the coinbase `auth_data_root` (coinbase digest via `compute_coinbase_auth_digest` with the stored branch id). Coinbase-only declarations carry no other txs, so the root is the single coinbase digest. If a declaration ever carries txs (full-template, deferred), validation falls back to the existing behavior for that flagged path — this spec's pool change targets the coinbase-only declarations the bundle produces,
  - `expected = calculate_block_commitments_hash(template.chain_history_root, auth_data_root)`,
  - reject unless `declared block_commitments == expected`. Typed error retained (now: "declared commitments don't verify against declared coinbase + chain tip").
- **Stored value:** `DeclaredJobInfo.block_commitments` keeps the JDC-declared (now-verified) value, so the existing `handle_push_solution` / `handle_submit_shares_jd` header reconstruction stays correct for the eventual block.

### Data flow

```
JDC:  getblocktemplate (chainHistoryRoot)
      + getblockchaininfo (consensus.nextblock = branch_id)
      → build coinbase from pool coinbase_output
      → recompute block_commitments → SetCustomMiningJob

Pool: each template cycle: store chainHistoryRoot + branch_id in CurrentTemplateContext
      → on declaration: recompute expected from the DECLARED coinbase (coinbase-only) → verify == declared
```

## Testing

- **Unit (JDC, `template_builder`):** recompute for a known coinbase + chainHistoryRoot + branch id matches a fixed expected value; coinbase-only `auth_data_root` == coinbase digest. Cross-check the fixture against an independently computed value — ideally reproduce the live bundle zebra's own `authdataroot`/`blockcommitmentshash` (`e2343c…`/`976e89…`) from that zebra's coinbase + branch id, proving the math against real consensus output.
- **Unit (pool, `validate_header_fields`):** accepts a correctly-declared job; rejects tampered `block_commitments`; rejects a declaration whose coinbase doesn't produce the declared commitments; chainHistoryRoot/branch id stored from the template.
- **Integration (the regression test that would have caught this):** extend the in-process chain test so the **pool's template provider and the JDC use different coinbase addresses** (the exact scenario that exposed the bug) — assert the declaration is now **accepted** and a share credits under the account. This requires the in-process harness to give the two sides distinct coinbase outputs (today it shares one zebra mock; the test must diverge them).
- **Live E2E:** re-run the Tier-2 bundle against the live testnet (internal miner quiesced); a declaration is accepted, a CPU-mined share is credited under the account, and a block-target solution is submitted and accepted by zebra.

## Out of scope

- Vardiff, attestation, Noise on the JDC listener (unchanged from prior workstream).
- The pool internal-miner racing (operational; handled by quiescing it on the testnet).
- Changing the JD wire protocol — `SetCustomMiningJob` already carries `block_commitments` and `coinbase_tx`; no message changes.

## Risks

| Risk | Mitigation |
|---|---|
| Fork zebra vs upstream zebra compute coinbase auth digest differently → JDC's recompute won't match what zebra expects at submitblock | The recompute uses `zcash-coinbase` (the repo's own ZIP-244 implementation), which is what produces blocks the pool's CoinbaseValidator already accepts. The live-E2E acceptance test (block submitted+accepted by zebra) is the backstop — if the digest math diverges from zebra consensus, the block is rejected and we catch it before flipping the flag. |
| `getblockchaininfo` adds an RPC per template poll | Branch id changes only at upgrade activation; cache it, refresh on height crossing an activation boundary (or simply re-fetch — it's cheap and local). |
| Full-template per-tx auth digests not currently surfaced by the provider | Provider change to expose them; covered by a unit test. Live chain has 0 mempool txs, so coinbase-only is the path the E2E exercises — full-template correctness is unit-tested. |
| Pool and JDC read branch id / chainHistoryRoot at slightly different moments → mismatch across a block boundary | Both already gate on prev_hash/tip (`StalePrevHash`); a tip move invalidates the declaration the same way it does today, and the JDC re-declares. |
