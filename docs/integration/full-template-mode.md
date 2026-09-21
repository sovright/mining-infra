# Full-Template Mode Guide

> **Unavailable:** This guide describes a planned protocol flow, not a deployable feature. The pool rejects Full-Template opt-in, and the server rejects FullTemplate declarations and use of existing FullTemplate jobs. Current-version consensus parsing, selected-fee payout authorization, and commitment validation must be completed before enablement. Keep `full_template_enabled` false; no static payout floor makes this mode safe.

Full-Template mode gives miners complete control over block construction, including transaction selection. This is the ultimate form of mining decentralization.

## Why Full-Template Mode?

### Censorship Resistance

In standard pool mining, the pool decides which transactions to include. This creates censorship risks:

- Pools could exclude transactions from certain addresses
- Pools could prioritize their own transactions
- Regulatory pressure could force pools to censor

With Full-Template mode, **you** decide which transactions to include.

### MEV Protection

Miner Extractable Value (MEV) refers to profits miners can extract by reordering or inserting transactions. In Full-Template mode:

- You see all pending transactions first
- You control transaction ordering
- You can include your own transactions

### Verification

With Full-Template mode, you build the block yourself and can verify:

- All included transactions are valid
- The coinbase correctly pays you
- No hidden transactions are included

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Your Setup                                  │
│                                                                     │
│   ┌────────────┐      ┌────────────────┐      ┌────────────────┐   │
│   │   Zebra    │─────▶│   JD Client    │─────▶│  Block Header  │   │
│   │  Mempool   │      │  tx selection  │      │  + Merkle Root │   │
│   └────────────┘      └───────┬────────┘      └────────────────┘   │
│                               │                                     │
│                               ▼                                     │
│                       ┌───────────────┐                            │
│                       │ SetFullTemplate│                            │
│                       │     Job       │                            │
│                       └───────┬───────┘                            │
│                               │                                     │
└───────────────────────────────┼─────────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │    Pool JD Server     │
                    │   (validates, tracks) │
                    └───────────────────────┘
```

## Enabling Full-Template Mode

### JD Client Configuration

```bash
zcash-jd-client \
  --zebra-url http://127.0.0.1:8232 \
  --pool-jd-addr pool.example.com:3334 \
  --user-id my-miner \
  --full-template \
  --tx-selection all
```

### Programmatic API

```rust
use zcash_jd_client::{JdClient, JdClientConfig, TxSelectionStrategy};

let config = JdClientConfig {
    zebra_url: "http://127.0.0.1:8232".to_string(),
    pool_jd_addr: "pool.example.com:3334".parse()?,
    user_identifier: "my-miner".to_string(),
    full_template_mode: true,
    tx_selection: TxSelectionStrategy::All,
    ..Default::default()
};

let client = JdClient::new(config)?;
client.run().await?;
```

## Transaction Selection Strategies

### Strategy: `All`

Include every transaction from your Zebra mempool:

```bash
--tx-selection all
```

**Pros:**
- Maximum fees
- No censorship
- Simple

**Cons:**
- May include low-fee transactions
- Block may be larger than optimal

### Strategy: `ByFeeRate`

Prioritize transactions by fee rate (zatoshis per byte):

```bash
--tx-selection by-fee-rate
```

**Pros:**
- Maximizes fee revenue per block size
- More efficient block space usage

**Cons:**
- May delay low-fee transactions

### Custom Strategy (Advanced)

Implement your own selection logic:

```rust
use zcash_jd_client::{Transaction, TxSelector};

struct MySelector {
    min_fee_rate: u64,        // Minimum zatoshis/byte
    max_transactions: usize,   // Max txs per block
    priority_addresses: Vec<String>,
}

impl TxSelector for MySelector {
    fn select(&self, mempool: Vec<Transaction>) -> Vec<Transaction> {
        let mut selected: Vec<Transaction> = mempool
            .into_iter()
            .filter(|tx| tx.fee_rate() >= self.min_fee_rate)
            .collect();

        // Prioritize certain addresses
        selected.sort_by(|a, b| {
            let a_priority = self.priority_addresses.contains(&a.sender());
            let b_priority = self.priority_addresses.contains(&b.sender());
            b_priority.cmp(&a_priority)
                .then(b.fee_rate().cmp(&a.fee_rate()))
        });

        selected.truncate(self.max_transactions);
        selected
    }
}
```

## Protocol Details

### Token Allocation with Mode

Request Full-Template mode when allocating a token:

```rust
AllocateMiningJobToken {
    request_id: 1,
    user_identifier: "my-miner",
    requested_mode: JobDeclarationMode::FullTemplate,
}
```

The pool responds with the granted mode:

```rust
AllocateMiningJobTokenSuccess {
    request_id: 1,
    mining_job_token: vec![...],
    coinbase_output: vec![...],  // Pool's payout script
    coinbase_output_max_additional_size: 256,
    async_mining_allowed: true,
    granted_mode: JobDeclarationMode::FullTemplate,  // Confirmed!
}
```

**Note:** If the pool doesn't support Full-Template, `granted_mode` will be `CoinbaseOnly`. Your client must respect this.

### SetFullTemplateJob Message

```rust
SetFullTemplateJob {
    channel_id: 1,
    request_id: 2,
    mining_job_token: token,

    // Block header fields
    version: 5,
    prev_hash: [u8; 32],
    merkle_root: [u8; 32],      // You compute this!
    block_commitments: [u8; 32],
    time: 1700000000,
    bits: 0x1d00ffff,

    // Coinbase
    coinbase_tx: vec![...],     // Must include pool payout

    // Transactions
    tx_short_ids: vec![[u8; 32]; N],  // Transaction IDs
    tx_data: vec![Vec<u8>; M],        // Full tx data (optional)
}
```

### Merkle Root Calculation

You must compute the merkle root yourself:

```rust
fn compute_merkle_root(coinbase: &[u8], transactions: &[Transaction]) -> [u8; 32] {
    let mut txids: Vec<[u8; 32]> = vec![
        double_sha256(coinbase)  // Coinbase txid first
    ];

    for tx in transactions {
        txids.push(tx.txid());
    }

    merkle_root_from_txids(&txids)
}

fn merkle_root_from_txids(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.len() == 1 {
        return txids[0];
    }

    let mut next_level = Vec::new();
    for pair in txids.chunks(2) {
        let left = pair[0];
        let right = pair.get(1).unwrap_or(&pair[0]);
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&left);
        combined[32..].copy_from_slice(right);
        next_level.push(double_sha256(&combined));
    }

    merkle_root_from_txids(&next_level)
}
```

### Missing Transactions Protocol

If the pool doesn't have some transactions in its mempool:

```
JD Client                         Pool JD Server
    |                                   |
    |-- SetFullTemplateJob ------------>|
    |   (txids: [A, B, C, D])           |
    |                                   |
    |<- GetMissingTransactions ---------|
    |   (missing: [B, D])               |
    |                                   |
    |-- ProvideMissingTransactions ---->|
    |   (transactions: [B_data, D_data])|
    |                                   |
    |<- SetFullTemplateJob.Success -----|
```

Your client caches transaction data to respond quickly:

```rust
// JD Client automatically caches transactions
client.cache_transaction(txid_b, tx_b_data);
client.cache_transaction(txid_d, tx_d_data);

// When pool requests missing txs, client responds from cache
```

## Pool Validation Levels

Pools can configure how strictly they validate Full-Template jobs:

### Minimal

Pool only verifies the coinbase includes the required pool payout:

```rust
ValidationLevel::Minimal
// Checks: pool_payout_script exists in coinbase outputs
```

### Standard (Default)

Pool verifies payout and requests missing transactions:

```rust
ValidationLevel::Standard
// Checks: pool payout + known txids
// Action: GetMissingTransactions for unknown txids
```

### Strict

Pool fully validates all transactions:

```rust
ValidationLevel::Strict
// Checks: pool payout + all txs valid + consensus rules
// Rejection: Any invalid transaction
```

## Coinbase Requirements

Your coinbase transaction **must** include the pool's payout output:

```rust
fn build_coinbase(
    pool_payout_script: &[u8],
    pool_payout_amount: u64,
    miner_payout_address: &str,
    miner_extra_amount: u64,
    block_height: u32,
    block_reward: u64,
) -> Vec<u8> {
    let mut outputs = vec![];

    // 1. Pool payout (REQUIRED)
    outputs.push(TxOutput {
        value: pool_payout_amount,
        script: pool_payout_script.to_vec(),
    });

    // 2. Miner payout (optional)
    if miner_extra_amount > 0 {
        outputs.push(TxOutput {
            value: miner_extra_amount,
            script: address_to_script(miner_payout_address),
        });
    }

    // 3. Founders reward / dev fund (if applicable)
    // ... (depends on block height and network rules)

    build_coinbase_transaction(block_height, block_reward, outputs)
}
```

## Error Handling

### ModeMismatch

```
Error: Token was not granted FullTemplate mode
```

The token was allocated for CoinbaseOnly but you sent SetFullTemplateJob. Request a new token with FullTemplate mode.

### InvalidCoinbase

```
Error: Coinbase doesn't include required pool payout
```

Your coinbase must include the pool's payout script with sufficient value.

### InvalidTransactions

```
Error: Transaction validation failed
```

One or more transactions are invalid. Check:
- Transaction format is correct
- Transactions are valid for current chain state
- No double-spends

### StalePrevHash

```
Error: Previous block hash does not match current chain tip
```

A new block was found. Fetch a new template and rebuild.

## Best Practices

### 1. Keep Zebra Synced

Your Zebra node must be fully synced. Stale templates = rejected jobs.

```bash
# Monitor sync status
watch -n 1 'curl -s http://127.0.0.1:8232 -d "{\"jsonrpc\":\"2.0\",\"method\":\"getblockchaininfo\",\"params\":[],\"id\":1}" | jq .result.blocks'
```

### 2. Minimize Latency

- Run Zebra on the same machine as JD Client
- Use low-latency connection to pool
- Set appropriate poll interval (500-1000ms)

### 3. Cache Transactions

Keep transaction data cached for GetMissingTransactions responses:

```rust
// Cache all transactions you include
for tx in &selected_transactions {
    client.cache_transaction(tx.txid(), tx.raw_data());
}
```

### 4. Handle New Blocks Quickly

When a new block is found:
1. Immediately stop mining current job
2. Fetch new template from Zebra
3. Rebuild and submit new job

### 5. Validate Before Submitting

Before sending SetFullTemplateJob, verify:
- Merkle root is correct
- Coinbase includes pool payout
- All transactions are valid
- prev_hash matches current tip

## Metrics to Monitor

```
# Template freshness
jd_client_template_age_seconds

# Transaction selection
jd_client_mempool_size
jd_client_selected_transactions
jd_client_total_fees_zatoshis

# Job status
jd_client_jobs_submitted_total
jd_client_jobs_accepted_total
jd_client_jobs_rejected_total{reason="stale"}
jd_client_jobs_rejected_total{reason="invalid_coinbase"}

# Missing transactions
jd_client_missing_tx_requests_total
jd_client_missing_tx_provided_total
```

## Security Considerations

### Validate Pool Response

Verify the pool's payout script hasn't changed unexpectedly:

```rust
if response.coinbase_output != expected_pool_payout {
    warn!("Pool payout script changed!");
    // Investigate before continuing
}
```

### Protect Your Mempool

Your mempool contains pending transactions. Protect access:
- Bind Zebra RPC to localhost only
- Use firewall rules
- Don't expose publicly

### Audit Your Selection

Log which transactions you're including for audit purposes:

```rust
info!(
    "Block template: {} txs, {} ZEC fees",
    selected.len(),
    total_fees_zec
);
for tx in &selected {
    debug!("Including tx: {}", tx.txid_hex());
}
```

## Comparison: Modes at a Glance

| Feature | Standard Pool | Coinbase-Only JD | Full-Template JD |
|---------|--------------|------------------|------------------|
| Who selects txs | Pool | Pool | **Miner** |
| Who builds coinbase | Pool | **Miner** | **Miner** |
| Censorship resistant | No | Partial | **Yes** |
| MEV protection | No | Partial | **Yes** |
| Complexity | Low | Medium | High |
| Zebra node required | No | Yes | Yes |

## Next Steps

- [JD Client Guide](./jd-client-guide.md) - Setup and configuration
- [Protocol Reference](./protocol-reference.md) - Complete message formats
- [Security Guide](./security-guide.md) - Hardening your setup
