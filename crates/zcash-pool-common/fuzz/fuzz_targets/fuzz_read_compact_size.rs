#![no_main]

use libfuzzer_sys::fuzz_target;
use zcash_pool_common::read_compact_size;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytes into read_compact_size.
    // Must not panic regardless of input -- only Ok or Err.
    let mut cursor = 0;
    let _ = read_compact_size(data, &mut cursor);

    // If first call succeeded, try reading again from the updated cursor
    // to exercise sequential reads on a single buffer.
    let _ = read_compact_size(data, &mut cursor);
});
