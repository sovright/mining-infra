# Confirmed transaction cache retention

Implement the user-approved delayed confirmed eviction in the shared relay TxCache and opt-in trusted-Zebra maintenance tasks for sidecar and ingress. Base upstream/main 5456ff5c. Keep production binaries/config untouched during implementation.

Policy: canonical block transaction IDs establish confirmation. Mempool absence, peer announcements and successful submissions do not. Retain cached confirmed payloads for at least 600 seconds AND 12 confirmations; periodically remove eligible confirmed payloads and prioritize them under admission pressure. Both bounds configurable positive. The hard byte/entry cap remains authoritative, so memory pressure can still force FIFO eviction before grace. Duplicate feed insertion cannot reset confirmation age. Trusted mempool reappearance clears a confirmation marker. On canonical anchor reorg, clear retained confirmation markers; already evicted payloads require refetch/fallback. No guarantee of retaining all payloads or handling arbitrary deep reorgs without fetch.

Implementation:
1. Shared metadata, mark/restore/reset/prune APIs, confirmed-entry/eviction metrics. Tests pin elapsed+depth grace, pending preservation, duplicates, bounds and index consistency.
2. Background canonical polling: getblockhash/getblock1 txids, bounded32 catchup, anchor revalidation including sameheight reorg, stable before/after tip, fail-safe RPC behavior. Local JSON-RPC tests exercise race/reorg/failure and eventual cleanup.
3. Sidecar TOML and ingress env opt-ins with defaults off, positive grace/depth validation, task wiring outside block hot paths. Preserve existing flags and cache caps. Export metrics and configuration docs.
4. Run fmt and focused shared+sidecar+ingress suites, clippy for touched crates, independent review; inspect exact diffs and fix findings. Preserve clean local commit and reviewable branch. Deployment is a separate artifact/canary gate.

Expected limitations: bounded recent canonical evidence is reapplied to late cache inserts; payloads from older blocks outside that window may remain until capacity eviction. Avoid unbounded historical txid metadata. RPC source trust and network identity require operator configuration. The current live binary digest is c329126b73157ed60f4202af01344916506aafed0c41e17124eb625451ecfa8b; source main is newer than local dirty checkout and must not be described as proven to match running binaries.

## Completed validation

- Full workspace: `RUSTFLAGS='' CARGO_INCREMENTAL=0 cargo test --workspace --offline` — 1,680 passed, 7 ignored, zero failed.
- Three touched crates: 896 passed, 3 ignored, zero failed.
- `RUSTFLAGS='' CARGO_INCREMENTAL=0 cargo clippy -p sovright-relay -p sovright-relay-sidecar -p sovright-p2p-ingress --all-targets --offline -- -D warnings` — passed.
- `cargo fmt --all -- --check` and `git diff --check` — passed.
- Independent review: fixed grace starting before slow RPC completion and FIFO admission evicting pending entries ahead of newly eligible confirmed entries; final review found no correctness blockers.
- Regression coverage includes capacity preference between maintenance ticks, duplicate preservation, both retention bounds, pending restoration, sameheight/rollback reorg, failed/malformed/moving snapshots, bounded catchup and recent-history replay, late payload insertion, and post-observation grace.

Live binary/source matching was limited to capturing the running digest; no build commit was exported in inspected identity fields. No deployment or production-cache behavior change is claimed. The implementation is based on refreshed upstream main, not a patch applied to the live binary. Operational settings and limitations are in `docs/operations/transaction-cache-retention.md`.
