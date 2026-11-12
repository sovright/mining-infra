# Supply-chain review policy

mining-infra gates its dependency tree with two CI checks, adopted from Argos:

- **`cargo vet`** (`supply-chain/config.toml`, `audits.toml`, `imports.lock`):
  every third-party crate must be covered by an imported audit, a first-party
  audit, or an exemption.
- **`cargo deny`** (`deny.toml` at the repo root): advisories (yanked crates
  fail), a license allow-list, wildcard bans, and crates.io-only sources.

## Where we start

`cargo vet init` followed by `cargo vet prune` against the imports below left:

```
112 fully audited, 4 partially audited, 338 exempted
```

Count exemptions with `grep -c '^\[\[exemptions\.' supply-chain/config.toml`.

An exemption is a standing waiver: the crate is accepted with no audit record.
**338 is a baseline to drive down, not a number to let grow.** When a
dependency is bumped, its new version needs a fresh exemption. Accepting that
as a one-line change in a routine update is exactly how a compromised point
release gets through without anyone reading it.

## Critical crates

These crates authenticate relay peers, carry the Noise transport, parse or
validate blocks before we submit them to Zebra, or rebuild blocks from
error-correction shards. A compromised release of any one could forge relay
traffic, get an invalid block submitted, or take down the relay. They must
**never be accepted on a blanket exemption alone**:

```
# relay authentication and transport
hmac  sha2  subtle  siphasher  blake2b_simd
snow  x25519-dalek  curve25519-dalek  chacha20poly1305  zeroize  rand

# block parsing and proof-of-work
zcash_primitives  zcash_protocol  zcash_encoding  zcash_transparent
orchard  sapling-crypto  equihash  zakura-equihash

# error correction (reed-solomon-erasure itself is vendored first-party code)
lru

# Zebra RPC and networking on the submit path
jsonrpsee-http-client  hyper  tokio  socket2  rustls  ring
```

When this policy was written, every one of these except `subtle` and
`zeroize` was covered only by an exemption. Converting them is the first
piece of follow-up work.

## Policy

1. **Exemption changes are a review trigger.** A PR that adds or version-bumps
   an exemption for a critical crate MUST state in its description that a
   reviewer read the upstream diff between the previously accepted version and
   the new one.

2. **Prefer audits or publisher-pinned trust over exemptions.** For critical
   crates, replace the exemption with a first-party `[[audits]]` entry (a real
   code review, recorded with `cargo vet certify`) or a publisher-pinned
   `[[trusted]]` entry:

   ```sh
   cargo vet trust <crate> <publisher-login> --criteria safe-to-deploy \
       --notes "Critical crate (see supply-chain/README.md); trusting the upstream publisher."
   ```

   Which crates.io accounts to trust is a maintainer decision and is deliberately
   not automated.

3. **Keep CI green by content, not by waiver.** When `cargo vet` fails after a
   bump, review and certify (or trust) the new version rather than widening an
   exemption. CI runs `cargo vet --locked`, which enforces the recorded set
   without fetching anything.

## Imported audits

`config.toml` imports audits from Bytecode Alliance, Embark, Fermyon, Google,
ISRG, Mozilla and Zcash (librustzcash), the same set Argos uses. Refresh them
deliberately with `cargo vet regenerate imports` and commit the resulting
`imports.lock`. Re-pull on every librustzcash or Zebra-aligned bump.

## Vendored code

`vendor/reed-solomon-erasure` is a patched copy of a crates.io crate (see its
`SOVRIGHT-PATCH.md`). `config.toml` sets `audit-as-crates-io = false` for it:
it is reviewed in this repository like our own crates, and its dependencies
(`lru`, `parking_lot`, `spin`, ...) are vetted as usual.
