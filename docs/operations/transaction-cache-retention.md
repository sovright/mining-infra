# Confirmed transaction cache retention

The relay cache is a reconstruction cache, not a replica of the current node mempool. Recently mined transactions must remain available for a late compact block, redundant delivery and shallow reorganizations.

The opt-in policy observes canonical blocks from a trusted Zebra-compatible node. It marks cache entries by transaction ID (all auth-digest variants) and removes them once **both** 600 seconds have elapsed since observation and 12 confirmations have been observed. Both bounds are configurable. Unconfirmed entries have no new expiry rule. A successful full mempool observation restores pending status; disappearance from the mempool alone never establishes confirmation.

Incoming transactions preserve the original confirmation marker on duplicate insertion. Capacity eviction prefers confirmed entries that meet both bounds using the last trusted chain height, then falls back to the existing FIFO policy. Hard memory/entry limits remain authoritative: recently confirmed or pending data can still be evicted under pressure. Retention is not a hard pin or an assurance of compact reconstruction success.

## Sidecar

Add these top-level fields to the existing sidecar TOML (before any table header):

```toml
tx_cache_enabled = true
tx_cache_confirmed_eviction_enabled = true
tx_cache_confirmed_grace_secs = 600
tx_cache_min_confirmations = 12
tx_cache_maintenance_interval_secs = 5
```

Uses the sidecar's existing `zebra_url`, independently of `zebra_mempool_sync_enabled`. The new policy defaults off; bare CLI keeps it off. Zero grace, confirmation count or polling interval is rejected when enabled. The opt-in requires an enabled cache.

Sidecar metrics add:

- `sovright_relay_sidecar_tx_cache_confirmed_entries`: cached entries with canonical confirmation evidence.
- `sovright_relay_sidecar_tx_cache_confirmed_evicted_entries_total`: payloads removed by confirmed expiry or confirmed-preferred capacity eviction.

Existing total eviction counters include these removals. Neither the confirmation count nor cache population alone measures reconstruction hit rate.

## P2P ingress

```sh
SOVRIGHT_P2P_TX_CACHE_ENABLED=true
SOVRIGHT_P2P_TX_CACHE_ZEBRA_URL=http://127.0.0.1:8232
SOVRIGHT_P2P_TX_CACHE_CONFIRMED_GRACE_SECS=600
SOVRIGHT_P2P_TX_CACHE_MIN_CONFIRMATIONS=12
SOVRIGHT_P2P_TX_CACHE_MAINTENANCE_INTERVAL_SECS=5
```

The explicit node URL enables maintenance; absent URL preserves existing behavior. Use an accessible trusted node on the **same network** as the ingress. The read-only endpoint is independent of the pool submitblock frontend. Do not configure an untrusted public peer as this authority. Credentials, query strings and fragments in the ingress URL are rejected. Maintenance never changes consensus or submission rules.

## Failure and recovery behavior

Canonical scans run outside block reconstruction/submission paths. Each pass validates block identity, parent links and a stable tip before applying cache mutations. The last anchor is revalidated even if height is unchanged. A detected reorg clears retained confirmation markers before applying replacement-chain evidence. Already removed payloads need refetching or the existing fallback paths; this is not an unlimited reorg archive.

RPC failures, malformed responses or a moving tip defer maintenance without voluntary expiry. The insertion hard cap still applies during an RPC outage. An unchanged tip does not invent new confirmations. Catch-up and recent canonical evidence are bounded to 32 blocks and 262,144 txids; large gaps reset confirmation state conservatively and scan the latest bounded range. Recent evidence is reapplied to late transaction arrivals. Payloads from older blocks outside that window may remain until capacity eviction.

Enable on one qualified canary after building the candidate, verify cache-confirmed entries rise and age out after both bounds, and compare reconstruction misses, pending coverage, raw fallback and submission outcomes. Rehearse delayed compact delivery, RPC failure and shallow reorg behavior in isolation. Expiry based only on block count would change wall-time retention at NU7; this policy requires a monotonic time bound as well.

Disabling the flag/URL and restarting returns to the previous bounded-cache behavior. No live configuration or binaries were changed as part of implementing this policy.
