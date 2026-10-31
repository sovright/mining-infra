# sovright-p2p-ingress

Native Zcash P2P ingress daemon for the Sovright relay network.

This is an MVP for timing and ingress experiments. It discovers Zcash mainnet
peers, performs the P2P handshake, listens for block inventory, requests block
payloads, and logs first-seen events. Optional crawler mode learns additional
peers from `addr` gossip and rotates through a bounded peer queue.

It does not consensus-validate blocks and does not submit blocks. Use Zebra as
the validation path.

## Run

```sh
RUST_LOG=info cargo run -p sovright-p2p-ingress
```

Useful environment variables:

```text
SOVRIGHT_P2P_DNS_SEEDS=dnsseed.z.cash,dnsseed.str4d.xyz,mainnet.seeder.zfnd.org,mainnet.is.yolo.money
SOVRIGHT_P2P_PEERS=1.2.3.4:8233
SOVRIGHT_P2P_MAX_PEERS=8
SOVRIGHT_P2P_CRAWLER_ENABLED=false
SOVRIGHT_P2P_CRAWLER_MAX_KNOWN_PEERS=5000
SOVRIGHT_P2P_CRAWLER_MAX_ADDR_PER_MESSAGE=1000
SOVRIGHT_P2P_CRAWLER_DRAIN_INTERVAL_SECS=5
SOVRIGHT_P2P_EVENT_LOG=/var/log/bedrock/zcash-p2p-ingress.jsonl
SOVRIGHT_P2P_RELAY_PEERS=10.40.0.3:8333
SOVRIGHT_P2P_RELAY_AUTH_KEY_HEX=<64 hex chars>
```

When crawler mode is enabled, the daemon still only makes outbound Zcash P2P
connections. It does not open an inbound listener, submit blocks, or forward to
FORGE unless the separate FORGE bridge settings are configured.

Measurement events include `p2p_connect_timing`, `p2p_handshake_timing`,
`p2p_ping_rtt`, `p2p_block_inv`, `p2p_getdata_sent`, and
`p2p_block_received`. These events are advisory telemetry only; crawler mode
does not rotate connections by score yet.

`p2p_block_received` is written as a block arrives, before it is parsed, and
counts deliveries. It no longer carries `miner_script` or `miner_tag`: those are on
a separate `p2p_block_coinbase` event, written once the body has parsed and matched
its header, whatever happens to the send. Join on `consensus_hash`, per block; do not
count it as a delivery. `hash` is the relay's internal id, not the chain's.

The line is best effort, with no exactly-once guarantee: a block can have no line,
one line or several, so consumers must process it idempotently. Lines that repeat a
pair of `miner_script` and `miner_tag` are duplicates. Different pairs under one
`consensus_hash` are a conflict, and a consumer must report no miner rather than pick
one, because one hash does not mean one body. See
[Block attribution](../../docs/integration/block-attribution.md) for the rule, the
migration order and sample data. Without a bridge, the first transaction is read
without validating the body against the header. Any extracted fields are emitted
as `p2p_block_coinbase_unverified`, not as validated attribution.

The FORGE bridge is disabled unless both `SOVRIGHT_P2P_RELAY_PEERS` and
`SOVRIGHT_P2P_RELAY_AUTH_KEY_HEX` are configured.
`SOVRIGHT_P2P_RELAY_DATA_SHARDS` and `SOVRIGHT_P2P_RELAY_PARITY_SHARDS`
override the default `10+3` FEC profile for relay traffic; they must match the
relay daemon and receiving sidecar.

## Refused block bodies

`forward_block` validates a block body before forwarding it. A refused body is
visible in two places:

- The Prometheus counter `sovright_p2p_ingress_block_body_rejected_total{reason}`
  counts refusals from P2P peers and the pool gateway. `reason` is one of
  `too_large`, `invalid_header_length`, `header_target`, `invalid_count`,
  `empty_transactions`, `transaction`, `transaction_boundary`, `trailing_bytes`,
  `duplicate_txid` and `merkle_mismatch`. It is the only label.
- The `p2p_block_body_rejected` JSON event identifies each refusal from a P2P
  peer, with `peer`, `hash`, `consensus_hash`, `reason`, `detail` and `bytes`.
  Pool gateway refusals are logged with their block hash instead.

The counter reaches Prometheus through a textfile, as the sidecar's do. Set
`SOVRIGHT_P2P_METRICS_TEXTFILE` to a `.prom` path that a textfile collector reads:

```text
SOVRIGHT_P2P_METRICS_TEXTFILE=/var/lib/sovright-p2p-ingress/metrics.prom
```

The file is rewritten every 30 seconds and starts at zero. It is written only
while the relay bridge is enabled, and testnet rejects the setting. Give each
process its own path: a collector refuses identical series from two files.

Nothing here is an alert. Monitoring needs the collector to read this path and a
rule of its own, for example:

```text
increase(sovright_p2p_ingress_block_body_rejected_total{reason="transaction"}[15m]) > 0
```

A block from a P2P peer must first have a header whose consensus hash meets the
target its own nBits state, within the network's limit. Anything else is refused as
`header_target` before it takes a parse permit. This is an anti-garbage check, not
proof of work: it does not verify the Equihash solution or the current difficulty,
a sender can pick an easy nBits, and a real header passes it with any body. The
pool gateway checks the target itself.

`transaction` and `trailing_bytes` can mean a valid block in a layout this reader
does not know, so they are the reasons to watch around a network upgrade.
`trailing_bytes` is reported only once the transactions match the header. A
refused hash that later appears on chain is only a lead, because a bad body can
carry a real block's header. It was a false rejection only if the node accepted
those same bytes, and the event records their length, not a digest. Parsing is not
consensus validation: these checks do not decide which transaction versions a
height allows, and a block that passes them can still be invalid.

### Emergency bypass for unreadable bodies

If the transaction reader meets a layout it cannot read, every valid block carrying
it is refused and the relay loses its speed advantage. Zebra still gets the block
over P2P, so the chain is not at risk. For that case, and only that case, there is a
bypass. It is off by default and has two independent switches:

```text
SOVRIGHT_P2P_RELAY_FORWARD_UNREADABLE_BLOCKS=true   # ingress
submit_unreadable_blocks = true                     # sidecar, under [submit_gate]
```

Zebra remains the consensus authority.

**A bypassed body has not passed the Merkle or duplicate-txid checks.** The reader
stopped before it had every txid, so neither check could run, and Zebra is the only
validator of those bytes. Only a `transaction` refusal qualifies. `trailing_bytes`,
`merkle_mismatch`, `duplicate_txid` and every other reason stay refused, including a
repeated txid among the transactions read before the failure.

| Still enforced | Ingress | Sidecar |
|---|---|---|
| Size and header length | Yes | Yes |
| Header meets its target, and a valid Equihash solution | Yes | Yes |
| One parse at a time, dedup | Yes | Gate lock, dedup |
| Parent and height window | No | Yes, the bypass needs the gate on |

A bypassed body goes out as raw segments only. It earns and costs the peer nothing,
has no coinbase line, and does not record its header as forwarded, so a forged body
cannot hide the real one in the ingress dedup. `unverified` is what the sender saw:
nothing on the wire says so, so each sidecar reads the body itself and applies its
own switch. Compact and short-ID candidates stay strict.

**Networks.** The proof-of-work check is the relay node's, limited to the mainnet
target range on either network. A testnet block inside that range qualifies. A
testnet minimum-difficulty block is refused at both ends, as it would be at the first
relay.

**Budgets.** These bound the cost of bodies nothing could check. They do not guarantee
recovery: a block that validates is outside them, but anyone holding a real header can
use them up before the real unreadable body arrives, and that body is then refused
until the budget refreshes. Honest copies of a block are identical, so they use one
place at ingress.

| | Ingress | Sidecar |
|---|---|---|
| Limits | Different bodies per header | Zebra attempts per block |
| Setting | `SOVRIGHT_P2P_RELAY_UNREADABLE_BODIES_PER_HEADER` | `unreadable_attempts_per_block`, under `[submit_gate]` |
| Default | 4, at least 1 | 4 |
| Refreshes | Each sent entry expires `SOVRIGHT_P2P_RELAY_FORWARD_DEDUP_WINDOW_SECS` (30) after send; a failed or cancelled attempt is released. The list holds the larger of `SOVRIGHT_P2P_RELAY_FORWARD_DEDUP_CAPACITY` (64) and the per-header limit, and refuses new unreadable bodies when full until an entry expires. In-flight entries never expire or get evicted | Each attempt `dedup_window_secs` (300) after it was made, whatever Zebra answered. The list holds `dedup_capacity` (256) entries, oldest out first |
| When used up | Refused as `transaction` | `unverified_limit` in `submit_gate_rejected_total` |

Ingress hashes a body on its bounded blocking pool before parsing. A previously sent
identical unreadable body skips parsing, Equihash and segmentation. A different body
must still be parsed before the unreadable-body budget applies: rejecting it by header
alone could suppress a valid copy. Thus this budget does not bound that parsing work.
An identical copy arriving while a send is in flight can be refused; if the send fails,
only a subsequent delivery retries it. A full global table can temporarily block new
unreadable bodies across headers; strictly validated blocks remain outside this budget.

A sidecar's budget is shared by every sender. Raising a budget buys room at the cost
of more unchecked work: at ingress one raw send of up to 2 MB per body, at the sidecar
what the next paragraph describes.

**Delivery.** A second body of one header does not cross the relay. Object ids come
from the header, so the relay delivers whichever body it saw first. A forged body that
reaches the mesh first therefore stops the real one on that path, whatever the budgets
say, until the upstream delivery race in #130 is fixed. Zebra still gets the block over
P2P.

**Waiting.** The receive task hands each unreadable block to a task of its own and
keeps reading, and the gate lock is held only to reserve an attempt and to record the
result. So an attempt waiting on Zebra holds up nothing else on that sidecar, valid
blocks included. A second copy of the same bytes is refused as a duplicate while the
first is out, and a different body of the same block runs alongside it, since it may
be the real one.

The sidecar records the block only once Zebra accepts it or answers `duplicate`. A dry
run, a rejection, an RPC error, a timeout or cancellation records nothing, so the next
copy is tried.

`unreadable_submit_budget_secs` under `[submit_gate]`, default 10, bounds one attempt's
async waits together: the parent lookup, the gate, `submitblock` and the lookup after a
rejection. It is not a wall-clock limit on the attempt: a timer cannot interrupt the
synchronous Equihash check, which can run past it, and that CPU time is unmeasured. Each
RPC also keeps its own 30 second limit, so a budget above that is not reached by one
call. When the budget runs out the attempt counts as failed, though Zebra may still
finish the block; the next copy then gets `duplicate`. At most
`unreadable_attempts_per_block` attempts run at once across all blocks, and more are
refused as `unverified_limit`. The default budget has not been checked against how
long Zebra takes to verify a large block.

The strict path is unchanged: it validates first, and then holds the gate lock and the
receive task through its own Zebra calls.

The Equihash check runs on the blocking pool under the parse permit at ingress, and on
the attempt's own task at the sidecar, where it occupies an async worker while it runs.
Its cost has not been measured on either.

The bypass does not cover the pool gateway's own validator, which refuses an unknown
transaction version before calling Zebra.

Nothing here is an alert until a rule exists. Rules to add, with a collector on both
textfiles:

```text
# A body the reader could not read. Investigate; it can also be junk from a peer.
increase(sovright_p2p_ingress_block_body_rejected_total{reason=~"transaction|trailing_bytes"}[15m]) > 0
increase(sovright_relay_sidecar_relay_block_body_rejected_total{reason=~"transaction|trailing_bytes"}[15m]) > 0

# A body went on without the Merkle and duplicate checks.
increase(sovright_p2p_ingress_block_body_unverified_forwarded_total[15m]) > 0
increase(sovright_relay_sidecar_relay_block_body_unverified_total[15m]) > 0

# The bypass was left on.
sovright_p2p_ingress_unreadable_block_forward_enabled == 1
sovright_relay_sidecar_unreadable_block_submit_enabled == 1
```

Also alert on a stale textfile, or these rules go quiet with the collector.

To decide whether to turn it on, take `consensus_hash` from `p2p_block_body_rejected`
and ask whether Zebra accepted that block. A hash on chain is only a lead, because a bad
body can carry a real header. It was a false rejection only if Zebra accepted the same
bytes. Turn on the sidecar first, then ingress, and turn both off once a reader fix
ships. Each forward is logged as `p2p_block_unverified_forwarded`, and each sidecar
attempt as a warning. Both list `checks_run` (`size`, `header`, `proof_of_work`) and
`checks_skipped` (`merkle`, `duplicate_txid`). A repeat among the transactions read
before the failure is refused, but that does not cover the body, so `duplicate_txid`
is listed as skipped.

With `SOVRIGHT_P2P_PEER_SCORING_ENABLED`, a refused body costs the peer
`SOVRIGHT_P2P_PEER_SCORE_ERROR`, except for those two reasons. Only a block that is
validated and sent on earns the delivery rewards: a deduplicated copy earns and
costs nothing.

## Inventory limits

Inventory request bookkeeping is bounded per peer connection. These optional
environment variables control the limits:

| Variable | Default | Meaning |
| --- | --- | --- |
| `SOVRIGHT_P2P_MAX_PENDING_BLOCKS` | `128` | Outstanding block requests per peer |
| `SOVRIGHT_P2P_MAX_PENDING_TXS` | `1024` | Outstanding transaction requests per peer |
| `SOVRIGHT_P2P_RECENT_INVENTORY_ENTRIES` | `4096` | Entries in each recent block-announcement, completed-block, and completed-transaction cache |
| `SOVRIGHT_P2P_REQUEST_TIMEOUT_SECS` | `30` | Response deadline, from 1 to 3600 seconds |

The existing `SOVRIGHT_P2P_TX_REQUEST_LIMIT_PER_INV` (default `256`) also limits
transaction requests from an individual inventory message. A zero pending limit
disables requests of that type; zero recent entries disables recent deduplication.
Outstanding requests remain deduplicated regardless of the recent-cache size.

When a request window is full, additional inventories are dropped without a retry
backlog. A later announcement may be requested after capacity becomes available.
Matching responses, `notfound`, expiry, and connection teardown free outstanding
request state. Expired and not-found items may be retried; completed items remain
deduplicated until evicted from the bounded recent cache. Duplicate announcements
do not extend response deadlines. Block announcement scoring remains independent
of request capacity. Transaction cache identities continue to come from received
payloads rather than request order.

### NU7 candidate compatibility

The mainnet ingress advertises protocol `170190` (ZIP 259). The transaction
parser is pinned to `zcash_primitives =0.31.0-pre.0` and
`zcash_protocol =0.11.0-pre.0`: the previous 0.10.x protocol dependency does not
recognize finalized NU7 branch ID `0x77190AD9`. Bumping only the advertised
version would leave NU7 transactions absent from the cache/compact path.

The NU7 parser regression fixtures establish structural decoding, not valid
proofs, signatures, or consensus acceptance. The v6 fixture changes a public
NU6.3 transaction's branch ID and therefore invalidates its original signatures;
the v5 fixture is an empty structural transaction. The historical v5/v6 digest
oracle tests remain in place. Eight additional transparent-only cases compare
v5/v6 txid and auth digests with a standalone Python implementation of ZIP 244
and ZIP 229. They cover NU7/NU6.3 branch separation, authorization-script changes,
and wire/display byte order. The generator uses only Python's standard library;
it does not derive expected values from the Rust parser. Reproduce the fixture:

```sh
python3 crates/sovright-p2p-ingress/tests/fixtures/generate_nu7_digests.py
cargo test -p sovright-p2p-ingress --locked nu7_transparent_digests_match_independent_reference
```

These synthetic spends have no real UTXO or valid signature and no shielded
bundles. Before deployment, qualify real NU7 transactions and blocks, shielded
digest agreement, full reconstruction/submission, and the exact prerelease
dependency build on testnet or an isolated network.

Set `SOVRIGHT_P2P_NETWORK=mainnet` (the default) or `testnet`. This selects
network magic, the default peer port (8233/18233), and advertised protocol
version (170190/170180). Unknown values fail startup. No arbitrary protocol
version override is supported.

Testnet is currently **observation-only**. It has no implicit DNS seeds; provide
explicit testnet peers or seeds. Relay peers, transaction-feed output, and the
submitblock RPC are rejected in testnet mode. Caches remain process-local and
all structured events carry `network`. Use a separate process and event-log
path, and keep that path out of mainnet collector inputs. Existing consumers
are not automatically made network-aware by the additional field.

```sh
SOVRIGHT_P2P_NETWORK=testnet \
SOVRIGHT_P2P_PEERS=127.0.0.1:18233 \
SOVRIGHT_P2P_EVENT_LOG=/tmp/sovright-testnet-observations.jsonl \
SOVRIGHT_P2P_PEER_RUNTIME_SECS=30 \
cargo run -p sovright-p2p-ingress --locked
```

Use an isolated testnet node for this example. A configured nonstandard port
still uses the selected network's magic; a wrong-network response fails framing.
Peer admission depends on the actual output path. A session with a relay bridge
or transaction feed requires the selected network's NU7 protocol floor from
startup. An observation-only session, with neither output, accepts `170120` and
newer. Testnet configuration currently prevents enabling either output.

The forwarding floor stays fixed before, during, and after activation, including
reorgs; neither peer-supplied height nor a calendar date can lower it. Existing
connections cannot renegotiate VERSION, and application messages are rejected
until VERSION admission and VERACK finish. Deploying this candidate restarts
connections under the new policy. This intentionally reduces the available
pre-activation peer pool; qualify peer diversity and freshness before rollout.
A claimed version is not proof of correct consensus behavior: full-node
validation and NU7 block/submission qualification remain required.
