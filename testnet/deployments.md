# Sovright Internal Testnet -- Deployment Status

For full operational runbooks (SSH, rebuild, troubleshooting), see the
canonical deployment doc: **[`../deployment.md`](../deployment.md)**.

This file tracks milestone status only.

## Milestone Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Zebra Node | Complete |
| 2 | Pool Server | Complete |
| 3 | Test Miner | Complete |
| 4 | Product Stack | Next |
| 5 | Payout Testing | Pending |

## Open Issue: Custom Testnet (low-priority)

The original plan uses a fully isolated custom testnet (`disable_pow = true`) so
blocks are produced instantly -- better for payout testing in Phase 5. Blocked on
a Zebra bootstrapping limitation: custom testnets can't get their genesis block
without peers, and Zebra blocks every known workaround.

**Fix when needed:** patch Zebra to accept a `genesis_hex` seed in config (~20
lines in `zebra-state`). Not blocking Phases 1-4.
