# Bedrock Internal Testnet — Deployment Status

## Phase 1: Zebra Node ✅ Complete
## Phase 2: Pool Server ✅ Complete
## Phase 3: Test Miner — Next

**GCP VM:** `zebra-testnet` — `34.72.217.47`, project `mining-pool-491623`, zone `us-central1-a`
**SSH:** `gcloud compute ssh zebra-testnet --project mining-pool-491623 --zone us-central1-a`

---

## Phase 1: Zebra Node

### What's running

- Docker container `zebra-testnet` using a custom-built `zebra-internal-miner` image (Zebra v4.3.0 + `internal-miner` feature compiled in)
- Standard Zcash testnet, no peers, internal miner active
- State at `/data/zebra`, synced to height ~3.2M
- RPC live on `:18232`, `getblocktemplate` returning valid templates

### Verify

```bash
# Block height + chain
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}' \
  http://34.72.217.47:18232

# Block template
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"getblocktemplate","params":[],"id":1}' \
  http://34.72.217.47:18232
```

### Redeploy

```bash
# On GCP VM — rebuild and restart Zebra container
docker build -t zebra-internal-miner testnet/
docker stop zebra-testnet || true
docker run -d --name zebra-testnet \
  -v /data/zebra:/data/zebra \
  -p 18232:18232 -p 18233:18233 \
  zebra-internal-miner start --config /config/zebrad.toml
```

### Files

| File | Purpose |
|------|---------|
| `testnet/Dockerfile` | Builds `zebra-internal-miner` image with `internal-miner` feature |
| `testnet/zebrad.toml` | Main Zebra config — standard testnet, internal miner, no peers |
| `testnet/zebrad-bootstrap.toml` | Bootstrap config — connects to public peers to populate state past Canopy |

---

## Phase 2: Pool Server

### What's running

- `zcash-pool-server` running in a `screen` session on the GCP VM
- Connects to Zebra at `http://127.0.0.1:18232`
- Stratum V2 listening on `0.0.0.0:3333` (external test miners can connect)
- Prometheus metrics on `127.0.0.1:9090`
- Pool logs show "new template" messages as Zebra mines blocks

### Verify

```bash
# Attach to pool screen session
gcloud compute ssh zebra-testnet --project mining-pool-491623 --zone us-central1-a
screen -r pool

# Prometheus metrics
curl http://127.0.0.1:9090/metrics
```

### Redeploy

```bash
# On GCP VM
screen -dmS pool bash -c 'cd ~/bedrock && cargo run --release --example run_pool_testnet -p zcash-pool-server 2>&1 | tee /tmp/pool.log'
```

---

## Phase 3: Test Miner — Next

Run `zcash-test-miner` pointing at the live pool to verify share submission end-to-end.

```bash
# From any machine with the repo
cargo run --release -p zcash-test-miner -- --pool-addr 34.72.217.47:3333
```

Expected: pool logs show accepted shares, `pool_shares_accepted_total` incrementing in Prometheus.

---

## Phase 4–5: Product Stack + Payouts

See top-level plan in `docs/plans/`.

---

## Open Issue: BedrockTestnet (low-priority)

The original plan uses a fully isolated custom testnet (`disable_pow = true`) so blocks are produced instantly — better for payout testing in Phase 5. Blocked on a Zebra bootstrapping limitation: custom testnets can't get their genesis block without peers, and Zebra blocks every known workaround.

**Fix when needed:** patch Zebra to accept a `genesis_hex` seed in config (~20 lines in `zebra-state`). Not blocking Phases 1–4.
