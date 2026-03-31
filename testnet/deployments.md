# Bedrock Internal Testnet — Deployment Status

## Phase 1: Zebra Node ✅ Complete

A Zebra full node is running on GCP serving live block templates.

**GCP VM:** `zebra-testnet` — `34.72.217.47`, project `mining-pool-491623`, zone `us-central1-a`
**SSH:** `gcloud compute ssh zebra-testnet --project mining-pool-491623 --zone us-central1-a`

### What's running

- Docker container `zebra-testnet` using a custom-built `zebra-internal-miner` image (Zebra v4.3.0 + `internal-miner` feature compiled in)
- Standard Zcash testnet, no peers, internal miner active
- State at `/data/zebra`, synced to height ~3.2M
- RPC live on `:18232`, `getblocktemplate` returning valid templates

### Verify it's healthy

```bash
# Block height + chain
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}' \
  http://34.72.217.47:18232

# Block template (pool server needs this)
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"getblocktemplate","params":[],"id":1}' \
  http://34.72.217.47:18232
```

### Files

| File | Purpose |
|------|---------|
| `testnet/Dockerfile` | Builds `zebra-internal-miner` image with `internal-miner` feature |
| `testnet/zebrad.toml` | Main Zebra config — standard testnet, internal miner, no peers |
| `testnet/zebrad-bootstrap.toml` | Bootstrap config — connects to public peers to populate state past Canopy |

---

## Phase 2: Pool Server — Next

Point `zcash-pool-server` at the live Zebra node on GCP.

```bash
# On the GCP VM
cargo build --release --example run_pool_testnet -p zcash-pool-server
cargo run --release --example run_pool_testnet -p zcash-pool-server
# Connects to Zebra at http://127.0.0.1:18232
# Stratum V2 on :3333 | Prometheus on :9090
```

Expected: pool logs show "new template" messages, Prometheus metrics exposed.

## Phase 3: Test Miner — After Phase 2

```bash
cargo run --release -p zcash-test-miner -- --pool-addr 34.72.217.47:3333
```

Expected: pool logs show accepted shares, `pool_shares_accepted_total` incrementing.

## Phase 4–5: Product Stack + Payouts

See top-level plan in `docs/plans/`.

---

## Open Issue: BedrockTestnet (low-priority)

The original plan uses a fully isolated custom testnet (`disable_pow = true`) so blocks are produced instantly — better for payout testing in Phase 5. Blocked on a Zebra bootstrapping limitation: custom testnets can't get their genesis block without peers, and Zebra blocks every known workaround.

**Fix when needed:** patch Zebra to accept a `genesis_hex` seed in config (~20 lines in `zebra-state`). Not blocking Phases 1–4.
