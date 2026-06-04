# Tier-2 Functional Core + Public Images — Design

Date: 2026-06-04
Status: Approved by Zaki (this session); spec review pending
Repos: `sovright/mining-infra` (this repo, branch `feat/tier2-images`), `sovright/Sovright-Mining-Pool` (bundle-side changes)
Predecessor: the Tier-2 testnet unblock (product repo spec `2026-06-04-tier2-testnet-unblock-design.md`, PR #71) made the pool's JD endpoint live and the Tier-2 bundle chain-correct. This workstream makes the Tier-2 mining path actually function and ships the two Docker images the bundle references.

## Problem

The Tier-2 sovereignty bundle's compose references `bedrock/translator-proxy:latest` and `bedrock/job-declarator:latest` — neither exists as an image. Worse, the topology it describes is not implemented:

- `zcash-jd-client` is client-only: it declares jobs to the pool's JD server but has **no downstream listener** — nothing can mine its declared jobs. The bundle expects the proxy to chain through it on `:34265`.
- The pool's JD server share/solution path is an explicit stub (`server.rs` PushSolution handler: unvalidated difficulty, synthetic `jd-miner-{channel}` ids, "NOT SAFE FOR PRODUCTION").
- The pool's stratum side never serves declared jobs — declared templates are validated, then nothing mines them.
- Neither binary reads the env vars the bundle sets; the bundle's `policy.toml` (inclusion preferences, guarantees, ed25519 attestation) has no implementation.
- `bedrock-v1-proxy` (SV1→V2 translator) IS implemented and reviewed on `sovright/main` (`--listen`/`--upstream` CLI), so the Tier-1 image is mostly packaging.

## Decisions made (with Zaki)

1. **Scope: functional core.** Implement the JDC downstream listener and a real share path so Tier-2 genuinely mines miner-declared templates. Parse `policy.toml` but honor only `include-all`; defer the preference/guarantee engine and attestation, and trim the bundle's promises to match.
2. **Registry: `ghcr.io/sovright/*`** (`job-declarator`, `translator-proxy`), published by GitHub Actions in this repo. Bundles pin version tags, never `latest`.
3. **Repo home: `sovright/mining-infra` `main`.** It already contained everything from `iqlusioninc` `internal-testnet` except the JD-env commit (cherry-picked onto this branch as `ecff303`) and the proxy spec doc (already present).
4. **Topology: Approach A — the JDC serves its declared jobs locally.** The miner's hashpower takes jobs only from the local JDC; the pool cannot substitute templates. Rejected alternative (pool reflects declared jobs to the account's stratum sessions) was cheaper but reintroduces the pool as a job source, gutting the censorship-resistance claim Tier-2 exists to make.

## Architecture (Tier-2 bundle, target state)

```
[ASIC / test miner] --SV1--> [translator-proxy :3333]
                                  | (--upstream, Bedrock V2)
                             [zcash-jd-client :34265]   <-- serves ONLY its declared job
                              |            |        \
               (getblocktemplate)   (JD protocol)    (submitblock on block hit)
                              |            |              |
                       [miner's Zebra]  [pool JD :34264]  [miner's Zebra]
```

Tier-1 is unchanged: proxy `--upstream` points at the pool directly.

## Components

### 1. JDC downstream listener (`crates/zcash-jd-client`, new `listener` module)

- Speaks the server side of the Bedrock-V2 subset the proxy consumes upstream: `SetupConnection`, channel open, `NewMiningJob` / `SetNewPrevHash`, `SetTarget`, `SubmitShares*`. Reuse `bedrock-strata`'s framing/codec/session machinery as a library — do not fork the protocol code.
- Serves exactly one job stream: the currently-declared job. On each new template from the miner's Zebra, the JDC re-declares to the pool and, on `SetCustomMiningJobSuccess`, broadcasts the new job downstream.
- Listen address: `JDC_LISTEN` env / `--jdc-listen` flag, default `0.0.0.0:34265`.
- **Not-ready behavior:** until Zebra is responding and a declaration has been accepted, the listener accepts TCP connections but issues no jobs (miners idle rather than mining a stale/wrong template). The proxy's existing reconnect/idle handling covers this.
- Proxy disconnects must not disturb the JD session with the pool.

### 2. Share path

- JDC validates downstream shares against its declared job: target check against the share target the pool granted, duplicate detection, job-id freshness. Invalid → standard V2 error to the proxy.
- Valid shares relay upstream over the existing JD connection via a new JD-protocol message `SubmitSharesJd { request_id, job_id, account (user_identifier), nonce/ntime/solution fields needed for independent verification }`. Response: success (with credited count) or typed error.
- **Pool side replaces the stub:** the JD server looks up the stored declared job for `job_id`, reconstructs the header, verifies Equihash and the share target for real, and credits `payout_tracker` under the declaring account's identity. Synthetic miner ids and unvalidated-difficulty crediting are removed. Errors return typed codes (unknown job, stale job, low difficulty, bad solution, duplicate).
- **Block path:** when a share meets the block target, the JDC assembles the full block (declared template + coinbase + solution) and submits it to the miner's own Zebra via the existing `block_submitter`, and also sends the existing `PushSolution` to the pool. The miner's node broadcasting its own block is the sovereignty story; PushSolution lets the pool account for found blocks.
- Vardiff: out of scope for v1 — the share target granted at declaration time stands for the session (testnet CPU miners; revisit before mainnet).

### 3. Env + identity

Clap `env` attributes (additive; CLI flags keep working):

| Binary | Env | Maps to |
|---|---|---|
| zcash-jd-client | `ZEBRA_RPC` | `--zebra-url` |
| zcash-jd-client | `POOL_SV2_ENDPOINT` | `--pool-jd-addr` |
| zcash-jd-client | `ACCOUNT_ID` | `--user-id` (→ `user_identifier`) |
| zcash-jd-client | `JDC_LISTEN` | `--jdc-listen` (new) |
| bedrock-v1-proxy | `SV1_LISTEN` | `--listen` |
| bedrock-v1-proxy | `UPSTREAM` | `--upstream` |

The bundle's Tier-1 `POOL_SV2_ENDPOINT` and Tier-2 `JDC_ENDPOINT` both map onto the proxy's `UPSTREAM` in the bundle's compose env wiring (product-side change; the proxy itself knows only `UPSTREAM`).

### 4. policy.toml — parsed, scoped honestly

- JDC reads `/etc/jdc/policy.toml` when present (`--policy` / `JDC_POLICY` to override the path).
- `[inclusion] mode = "include-all"` → accepted (matches existing `--tx-selection all`).
- Any other mode, or unknown keys implying unimplemented behavior → **refuse to start** with a clear "not yet supported" message. Silent acceptance of a policy we don't enforce is the one unforgivable failure mode for this product.
- `[attestation]` section → warn-and-ignore (named as deferred in the warning).
- No policy file → current behavior unchanged.

### 5. Images + publishing (this repo)

- `docker/Dockerfile.job-declarator` and `docker/Dockerfile.translator-proxy`: multi-stage, `rust:<pinned>` builder → `debian:bookworm-slim` runtime, non-root user, binary + minimal runtime deps only.
- `.github/workflows/images.yml`: build + push both images to GHCR on pushes to `main` (tag `edge`) and on `v*` tags (semver tags + `latest`). Uses the repo's `GITHUB_TOKEN` with `packages: write`.
- First release: tag `v0.1.0` once E2E passes.

### 6. Product-side bundle updates (`Sovright-Mining-Pool`, new branch)

- Image refs → `ghcr.io/sovright/translator-proxy:v0.1.0`, `ghcr.io/sovright/job-declarator:v0.1.0`.
- Tier-1/Tier-2 compose env aligned to the table above (`UPSTREAM` wiring; `JDC_ENDPOINT=jdc:34265` becomes real).
- Generated policy.toml trimmed to the `[inclusion] mode = "include-all"` section; preferences/guarantees/attestation move to a commented roadmap note.
- README: attestation/guarantee language moved to a roadmap paragraph; no promises the binaries don't keep. Bundle tests updated, including assertions that the rendered Tier-2 output contains no attestation config and pins both image tags.

## Testing

- **Unit:** listener session lifecycle (connect → job → share → new template → re-job); JDC share validation (good/stale/low-diff/duplicate); pool-side `SubmitSharesJd` validation against a stored declared job (each typed error + the credit path); policy parsing (absent / include-all / unsupported mode / attestation-ignored).
- **Integration (in-process, follows existing repo patterns):** pool + JDC + proxy + V1 test miner loop on a mock/regtest template provider — assert a declared job's share credits the correct account in `payout_tracker`, and a block-target solution triggers both `submit_block` (to the miner-side Zebra mock) and `PushSolution`.
- **E2E (live testnet):** run the real Tier-2 bundle compose from a laptop against `34.28.134.13`: local Zebra joins the chain (verified path from the previous workstream), JDC declares to `:34264`, CPU miner mines via the proxy, share appears against the right account via the portal API. Block submission verified opportunistically (CPU finds testnet blocks at 0x0f difficulty within minutes).

## Error handling principles

- JDC never serves a job it hasn't successfully declared. No fallback to pool jobs inside the JDC — fallback is an operator decision (point the proxy at the pool), not silent behavior.
- All cross-component failures are loud and typed: declaration rejected, share rejected, Zebra unreachable, policy unsupported.
- The pool treats `SubmitSharesJd` as untrusted input: full verification before any credit.

## Out of scope

- Policy preference/guarantee engine; attestation signing/publishing.
- Full-template mode hardening (exists behind `--full-template`; not part of this E2E).
- Vardiff on the JDC session.
- Flipping `ENABLE_TIER_2_BUNDLE` (separate go/no-go after E2E).
- Noise encryption on the JDC downstream listener (pool-side JD Noise support exists; revisit with mainnet hardening).

## Risks

| Risk | Mitigation |
|---|---|
| `bedrock-strata` server machinery isn't cleanly reusable as a library | Surfaced in the first implementation task; fallback is a minimal standalone server speaking only the required subset (the proxy exercises a narrow surface) |
| Pool-side Equihash verification cost per share | Testnet share rates are trivial; benchmark before mainnet, consider sampling then — not now |
| Declared-job/share race on template changes (share for job N arrives after job N+1 declared) | Pool keeps a small window of recent declared jobs per account (e.g. last 4) and validates against the matching one; stale beyond window → typed stale error |
| GHCR org permissions for first publish | One-time manual check that Actions in `mining-infra` may write packages to the `sovright` org |
