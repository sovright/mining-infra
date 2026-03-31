# Bedrock Internal Testnet — Deployment Status

## Phase 1: Zebra Node ✅ Complete
## Phase 2: Pool Server ✅ Complete
## Phase 3: Test Miner ✅ Complete
## Phase 4: Product Stack — Next

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

## Phase 3: Test Miner

### What's running

- `zcash-test-miner` connects to the pool server and submits dummy shares
- Tests the full Stratum V2 protocol flow: connection, job receipt, share submission
- Shares are dummy (random solutions) — validates protocol, not Equihash

### Run on GCP VM (Docker)

```bash
# Build the test miner image (from repo root)
docker build -f testnet/Dockerfile.test-miner -t bedrock-test-miner .

# Run against the local pool server
docker run -d --name test-miner --network host \
  bedrock-test-miner --pool 127.0.0.1:3333 --rate 5

# View logs
docker logs -f test-miner
```

### Run from dev machine

```bash
# Point at the GCP VM's public IP
cargo run --release -p zcash-test-miner -- --pool 34.72.217.47:3333 --rate 5
```

### Verify

```bash
# Pool logs should show share submissions
screen -r pool  # look for "share" messages

# Prometheus should show share counter incrementing
curl -s http://127.0.0.1:9090/metrics | grep pool_shares
```

### Redeploy

```bash
# On GCP VM
docker stop test-miner && docker rm test-miner
docker build -f testnet/Dockerfile.test-miner -t bedrock-test-miner .
docker run -d --name test-miner --network host \
  bedrock-test-miner --pool 127.0.0.1:3333 --rate 5
```

### Files

| File | Purpose |
|------|---------|
| `testnet/Dockerfile.test-miner` | Multi-stage build for the test miner binary |
| `crates/zcash-test-miner/src/main.rs` | Test miner source — CLI args, SV2 protocol client |

---

## Phase 4: Product Stack — Next

Deploy the Bedrock product portal (API + Frontend + TimescaleDB) on the same VM.
See `Bedrock-product/deployment.md` for full instructions.

### Quick start

```bash
# On GCP VM — clone and deploy
git clone https://github.com/<org>/Bedrock-product.git ~/Bedrock-product
cd ~/Bedrock-product/testnet
cp .env.example .env
# Edit .env: set JWT_SECRET to a random 32+ char string
docker compose build && docker compose up -d
```

### What it provides

- **TimescaleDB** on port 5433 — time-series storage for shares, hashrate, payouts
- **Bedrock API** on port 8080 — REST API for miner/admin dashboards, FPPS payouts
- **Frontend** on port 3000 — SvelteKit web portal

### Wiring

The API connects to services already running on the VM:
- Pool Prometheus metrics at `http://127.0.0.1:9090/metrics` (5s polling)
- Zebra RPC at `http://127.0.0.1:18232` (for payout sweeps)

### GCP firewall

```bash
gcloud compute firewall-rules create bedrock-product-testnet \
  --allow tcp:3000,tcp:8080 \
  --source-ranges 0.0.0.0/0 \
  --target-tags bedrock-testnet \
  --project mining-pool-491623
```

---

## Phase 5: Payout Testing

Requires a funded testnet wallet on the Zebra node. Steps:
1. Generate a unified address on the Zebra node
2. Fund it via testnet faucet or internal miner coinbase
3. Set `PAYOUT_FROM_ADDRESS` in the product `.env`
4. Register a miner via the frontend, accumulate balance, trigger sweep

---

## Open Issue: BedrockTestnet (low-priority)

The original plan uses a fully isolated custom testnet (`disable_pow = true`) so blocks are produced instantly — better for payout testing in Phase 5. Blocked on a Zebra bootstrapping limitation: custom testnets can't get their genesis block without peers, and Zebra blocks every known workaround.

**Fix when needed:** patch Zebra to accept a `genesis_hex` seed in config (~20 lines in `zebra-state`). Not blocking Phases 1–4.
