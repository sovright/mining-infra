# Luxor relay delivery instrumentation and scheduling experiment

The relay arrival timestamp is PoW validation of the reconstructed **segment-zero
header**, not reconstruction of a full raw block. P2P arrival logs record a full
block. Their difference must not be described as a full-block speedup.

## Immediate peer attribution

The existing `relay_block_received` JSONL event keeps `hash` and
`observed_at_unix_ms` for old readers. New fields describe the immediate session:
`source_key_id`, `source_role` (`full` or `receive_only`), `authenticated`, and
`stage: header_pow_validated`. No addresses or secret key material are recorded.
`assembly_elapsed_ms` uses the monotonic assembly timer; the estimated wall-clock
assembly start is explicitly named an estimate. Neither timer starts at the
pool's solve or send event. A receipt does not prove mining origin, complete-block
delivery, successful forwarding, or node acceptance.

Identity comes from the verified session, never the packet's claimed identity.
Bad HMAC packets cannot create receipts. Duplicate chunks do not create another
receipt in that assembly. Consumers must deduplicate reconnects by host/hash and
must count only authenticated Full-role receipts for direct submission evidence.
Header extraction reuses the validation decode, avoiding an extra FEC decode.

## Scheduler experiment (off by default)

`SOVRIGHT_RELAY_FORWARD_ROUND_ROBIN=true` interleaves one packet per peer, keeping
packet order within each peer. A single burst counter spans all destination
peers. Missing/false/0 preserves sequential scheduling and existing pacing.
Unknown values fail startup. This setting does not change receive permissions,
HMAC generation, PoW validation, or successful-send accounting.

Reproduce the controlled loopback experiment:

```sh
cargo test -p sovright-relay --lib benchmark_forward_scheduling -- --ignored --nocapture
```

The test checks every packet's HMAC and uniqueness and measures first packet and
final batch packet. It uses 64 packets of 512 bytes per peer, burst 16, delay 1 ms,
four/eight peers, three trials per mode. It is a debug-build loopback diagnostic,
not full-block reconstruction, WAN performance, or production qualification.

September 15 local results (median across three trials, milliseconds):

| Peers | Mode | Last peer first packet | Earliest batch complete | Last batch complete |
| --- | --- | ---: | ---: | ---: |
| 4 | Sequential | 32.56 | 19.13 | 40.08 |
| 4 | Interleaved | 9.46 | 47.89 | 48.35 |
| 8 | Sequential | 66.75 | 27.48 | 73.89 |
| 8 | Interleaved | 18.41 | 98.86 | 99.55 |

**Decision: keep sequential scheduling.** Earlier first packets do not offset the
completion regression. Aggregate pacing also inserts waits between peer batches
that sequential pacing skips; this is part of the measured behavior. Before any
scheduler rollout, repeat with optimized Linux binaries, production batch sizes,
real raw-block reconstruction, WAN delay/loss, and identical aggregate budgets.

## Attribution-only canary

This branch includes the already-deployed auth/rate-limit hardening prerequisite;
do not replace a deployed relay with an upstream binary that omits it.

1. Build and test the exact candidate on Linux. Record binary digest and retain
   the running binary, unit and environment for rollback.
2. Upgrade the passive collector first; configure its `pool.relay_key_id` using
   the existing invite identity. Do not add pool RPCs or enable submitblock.
3. Canary one relay with round-robin explicitly false, preserving its entire
   existing environment/key configuration. Verify service health, authenticated
   sessions, forwarding counters, send errors, and no new collection backlog.
4. Observe a real segment-zero receipt. Confirm new fields reach private report
   JSON, with the expected authenticated role. Lack of new blocks is pending
   evidence, not a failed canary or a reason to generate production traffic.
5. Compare receipt coverage and arrival-log growth before rolling other relays
   one at a time. Roll back on service failure, session loss, new sustained send
   errors, or collector lag; restore the old binary without changing evidence.

Destination `chunks_forwarded_by_key` counts traffic **to** a peer. Never use it
as a count of that peer's inbound submissions. The next useful timing hooks are
complete raw-block reconstruction and node acceptance, joined by consensus hash,
plus pool solve/send and replacement-job timestamps when available.
