#![no_main]

use libfuzzer_sys::fuzz_target;
use zcash_pool_common::{read_compact_size, write_compact_size};

fuzz_target!(|value: u64| {
    // Encode the value
    let mut buf = Vec::new();
    write_compact_size(value, &mut buf);

    // Decode it back
    let mut cursor = 0;
    let decoded = read_compact_size(&buf, &mut cursor)
        .expect("read_compact_size must succeed on output of write_compact_size");

    // Roundtrip must preserve value
    assert_eq!(value, decoded, "roundtrip mismatch for {}", value);

    // Cursor must consume all bytes
    assert_eq!(cursor, buf.len(), "cursor not at end for {}", value);
});
