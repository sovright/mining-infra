# Block attribution from ingress events

This is the contract for anything that attributes blocks to pools from the
`sovright-p2p-ingress` event log.

## Migration order

`p2p_block_received` no longer carries `miner_script` or `miner_tag`. They moved to
`p2p_block_coinbase`, so consumers must change first:

1. Update consumers to read both formats.
2. Deploy the consumers and check them against the sample below.
3. Deploy the ingress build.

Consumers keep reading both formats afterwards. Old logs have the fields on
`p2p_block_received`, and so does an old binary after a rollback.

## Events

| Event | Meaning | Carries miner fields |
|---|---|---|
| `p2p_block_received` | A delivery arrived. Count this for deliveries | Only in logs from older builds |
| `p2p_block_coinbase` | A body parsed and matched its header | Yes |
| `p2p_block_coinbase_unverified` | A no-relay observer parsed only the first transaction; the body was not checked against the header | Yes, unverified |
| `p2p_block_body_rejected` | A body was refused | No |
| `p2p_block_unverified_forwarded` | The emergency bypass sent a body without the Merkle and duplicate checks | No |

Join on `consensus_hash`, the hash Zebra reports. `hash` is the relay's internal id.

## What to expect

`p2p_block_coinbase` is best effort. A block can have no line, one line or several,
so consumers must process it idempotently and must not treat it as a delivery.

| Case | Lines |
|---|---|
| Validated and sent | One, written before the send |
| Validated, then the send failed or was cancelled | One. A later copy that sends it writes another |
| Two copies parsed at the same moment | Two |
| Pool gateway block | One, with `peer: "pool_gateway"`. Later P2P copies are deduplicated: a receipt, no line |
| Deduplicated copy | None for that delivery. It was not parsed |
| Unparseable or refused body | None. Its coinbase is not bound to the header |
| Sent under the emergency bypass | None. Nothing read the coinbase |
| Event log write failed | None. The block is still forwarded |
| Coinbase with nothing to report | None |

Lines can arrive after the receipt, or before it in a log merged from several
sources. Do not depend on order, and do not pick the first or last line.

## Attribution rule

For each `consensus_hash`, collect the distinct `(miner_script, miner_tag)` pairs from
`p2p_block_coinbase` lines and from any `p2p_block_received` line that carries miner
fields. Ignore `p2p_block_coinbase_unverified` for this rule. Legacy receipt fields
also lack body-validation evidence; retain their provenance and do not treat them
as proof that the reported body matched the header. A field that is absent is part
of the pair.

| Distinct pairs | Result |
|---|---|
| None | `unknown` |
| One, however many lines repeat it | That miner |
| More than one | `conflict`. Keep the evidence, report no miner |

A repeat and a conflict are different things. Lines with the same pair are duplicates
and collapse to one. Lines with different pairs mean two bodies said different things
under one hash, and nothing in the log says which one the chain has. Do not guess.

## What attribution does not show

One `consensus_hash` does not mean one body or one `miner_tag`. The Merkle root does
not cover authorization data, so two bodies can share a hash. From v5 on, `miner_tag`
comes from `scriptSig`, which is outside the txid, so it speaks only for the body it
was read from. `miner_script` comes from a transparent output and is covered.

A join preserves the provenance of its observations: validated coinbase events
and legacy receipt fields do not provide the same body-validation evidence. Even
a validated event does not show that every byte of that body is what the chain has.

## Sample

Run a consumer against these before deploying:

- `crates/sovright-p2p-ingress/tests/fixtures/block_attribution_sample.jsonl` holds the
  log lines: out of order, duplicate, conflicting, missing, gateway, and old and new
  formats mixed.
- `crates/sovright-p2p-ingress/tests/fixtures/block_attribution_expected.json` holds
  the result for each hash.

`crates/sovright-p2p-ingress/src/attribution_tests.rs` is a reference implementation
of the rule, tested against both files and against lines from the real event writer.
