# zcash-equihash-validator

Equihash solution validation and difficulty management for Zcash mining.

## Overview

This crate provides:

- **EquihashValidator** - Verifies Equihash (200,9) solutions
- **VardiffController** - Adaptive difficulty adjustment per-miner
- **Difficulty utilities** - Target/difficulty conversion functions

## Usage

### Solution Verification

```rust
use zcash_equihash_validator::EquihashValidator;

// Create validator (uses Zcash parameters: n=200, k=9)
let validator = EquihashValidator::new();

// Verify a solution
let header: [u8; 140] = /* 140-byte header including nonce */;
let solution: [u8; 1344] = /* 1344-byte Equihash solution */;

validator.verify_solution(&header, &solution)?;

// With difficulty check
let target: [u8; 32] = /* 256-bit target */;
let hash = validator.verify_share(&header, &solution, &target)?;
```

### Variable Difficulty (Vardiff)

```rust
use zcash_equihash_validator::{VardiffController, VardiffConfig};
use std::time::Duration;

let config = VardiffConfig {
    target_shares_per_minute: 5.0,
    min_difficulty: 1.0,
    max_difficulty: 1_000_000_000.0,
    retarget_interval: Duration::from_secs(60),
    variance_tolerance: 0.25,
};

let mut vardiff = VardiffController::new(config);

// On share received
vardiff.record_share();

// Periodically check for retarget
if let Some(new_diff) = vardiff.maybe_retarget() {
    // Send SetTarget message to miner
    let target = vardiff.current_target();
}
```

### Difficulty Utilities

```rust
use zcash_equihash_validator::{
    compact_to_target,
    target_to_difficulty,
    difficulty_to_target,
};

// Convert compact (nbits) to full target
let target = compact_to_target(0x1d00ffff);

// Convert between target and difficulty
let difficulty = target_to_difficulty(&target);
let back_to_target = difficulty_to_target(difficulty);
```

## Equihash Parameters

Zcash uses Equihash (200, 9):
- n = 200, k = 9
- Solution size: 1344 bytes (512 x 21-bit indices)
- Memory requirement: ~144 MB for solving
- Solve time: ~15-30 seconds on ASIC hardware

## Block Header Format

The 140-byte header consists of:
- Bytes 0-107: Header prefix (version, prev_hash, merkle_root, etc.)
- Bytes 108-139: 32-byte nonce

The solution is appended separately (with CompactSize prefix) for block hashing.

## Vardiff Algorithm

The adaptive difficulty controller:
1. Tracks shares submitted per miner
2. Calculates actual share rate vs target rate
3. Adjusts difficulty if rate is outside tolerance
4. Applies smoothing to avoid large jumps
5. Clamps within configured min/max bounds

Default configuration targets 5 shares/minute per miner, suitable for Equihash ASICs.

## Dependencies

- `equihash` crate (zcash-hackworks) for core verification
- `zcash-pool-common` for the double-SHA256 proof-of-work hash, shared with the
  test miner and the relay so the rule has one implementation

## License

MIT OR Apache-2.0
