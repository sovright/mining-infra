# Sovright patch of reed-solomon-erasure 6.0.0

This is the crates.io package `reed-solomon-erasure` 6.0.0 (package sha256
`7263373d500d4d4f505d43a2a662d475a894aa94503a1ee28e9188b5f3960d4f`, upstream
git `a1ca49de`). The workspace uses it through `[patch.crates-io]` in the root
`Cargo.toml`.

## Why

Upstream has not released since 6.0.0 (September 2022), and its `master` still
pins `lru = "0.7.8"`:

- `lru` 0.7.8 is unsound: RUSTSEC-2026-0253, a possible use-after-free if a
  panic happens in `LruCache::pop()`. Fixed in `lru` 0.18.2.
- `parking_lot` 0.11 pulls in `instant` (RUSTSEC-2024-0384, unmaintained),
  `parking_lot_core` 0.8, and through `lru` 0.7, `ahash` 0.7 and `hashbrown`
  0.12.
- `spin` 0.9 resolved to the yanked 0.9.8.

## What changed

The first commit adds the package unmodified. The patch commit after it
changes only:

| File | Change |
|---|---|
| `Cargo.toml`, `Cargo.toml.orig` | `lru` 0.7.8 → 0.19, `parking_lot` 0.11.2 → 0.12, `spin` 0.9.2 → 0.10 |
| `src/core.rs` | `DATA_DECODE_MATRIX_CACHE_CAPACITY` becomes a `NonZeroUsize`, because `LruCache::new` takes one since `lru` 0.8 |

Encoding and decoding output does not change. The LRU only memoizes decode
matrices that were already computed.
`crates/sovright-relay/tests/fec_known_answer.rs` pins the shard bytes
recorded with the unpatched crate, and also runs enough erasure patterns to
exercise the cache's eviction path.

The version stays 6.0.0 so that `[patch.crates-io]` applies to the existing
`reed-solomon-erasure = "6.0"` requirement.

## Dropping the patch

Remove this directory and the `[patch.crates-io]` entry once upstream publishes
a release with `lru` >= 0.18.2, or replace the crate. Any replacement codec
must reproduce the parity bytes pinned by `fec_known_answer.rs`.
