# Sovright Rebrand Design

**Date:** 2026-06-03
**Status:** Approved

## Goal

Rebrand the repository from Bedrock/Forge branding to **Sovright — Zcash Mining Pool and Relay Network**. All Bedrock and Forge naming is discarded. This is a clean break: no compatibility shims for old crate names, config keys, or metric names.

## Crate Renames

Rename crate directories, `Cargo.toml` package names, workspace member entries, and every dependency/`use` reference:

| Current | New |
|---|---|
| `bedrock-forge` | `sovright-relay` |
| `forge-sidecar` | `sovright-relay-sidecar` (binary name: `relay-sidecar`) |
| `bedrock-noise` | `sovright-noise` |
| `bedrock-strata` | `sovright-telemetry` |
| `bedrock-v1-proxy` | `sovright-v1-stratum-proxy` |

The `zcash-*` crates keep their names; only their internal references to renamed crates change.

## Code Identifiers

- `ForgeRelay` → `RelayClient`
- `crates/zcash-pool-server/src/forge.rs` → `relay.rs` (module `forge` → `relay`)
- `crates/zcash-pool-server/tests/forge_integration_test.rs` → `relay_integration_test.rs`
- Pool server config keys: `forge_relay_*` → `relay_*`. The `noise_*` keys are unchanged.
- Prometheus metric names in `sovright-telemetry`: any `bedrock_` or `forge_` prefix → `sovright_`. This breaks existing dashboards/alerts; flag prominently in `deployment.md`.
- "FORGE" / "Forge" / "Bedrock" in comments, log messages, error strings, and tracing targets → "relay network" / "Sovright" as appropriate.

No deprecation or fallback handling for old config keys: deployment is at internal-testnet stage, so the clean break is acceptable.

## Documentation

**Fully rebranded (living docs):**
- `README.md` — new title: "Sovright — Zcash Mining Pool and Relay Network"
- `CLAUDE.md` — project overview, crate dependency graph, key files, config field names
- `deployment.md` — including a note on the breaking config-key and metric-name changes
- Crate-level `README.md` files
- `docs/integration/*` (operator and miner guides)

**Left untouched (historical records):**
- `docs/plans/*`
- `docs/superpowers/plans/*` and dated specs under `docs/superpowers/specs/*` (other than this document)
- `crates/*/docs/plans/*` (move with their crate directory but contents unchanged)

## GitHub

- Rename `sovright/bedrock` → `sovright/mining-infra` via `gh api` (GitHub auto-redirects the old URL).
- Update the local `bedrock` git remote: rename the remote to `sovright` and point it at the new URL.
- The `origin` remote (`iqlusioninc/zcash-mining-infra`) is left as-is.

## Verification

- `cargo build --release` succeeds.
- `cargo test` passes.
- `cargo clippy` is clean.
- `grep -ri -E 'bedrock|forge'` over `*.rs`, `*.toml`, and living docs returns zero hits; remaining hits exist only in historical plan/spec documents.

## Out of Scope

- Any change to the `iqlusioninc/zcash-mining-infra` remote or repo.
- Rewriting historical planning documents.
- Compatibility shims of any kind.
