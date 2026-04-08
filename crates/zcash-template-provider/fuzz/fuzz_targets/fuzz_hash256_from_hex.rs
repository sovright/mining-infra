#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_template_provider::types::Hash256;

fuzz_target!(|data: &[u8]| {
    // Test with arbitrary bytes interpreted as a UTF-8 string
    if let Ok(s) = std::str::from_utf8(data) {
        // from_hex: display-order (big-endian), must never panic
        let _ = Hash256::from_hex(s);

        // from_hex_le: internal-order (little-endian), must never panic
        let _ = Hash256::from_hex_le(s);
    }

    // Also test with raw bytes as a hex-encoded string
    let hex_str = hex::encode(data);
    let _ = Hash256::from_hex(&hex_str);
    let _ = Hash256::from_hex_le(&hex_str);

    // Roundtrip: if from_hex succeeds, to_hex and re-parse should roundtrip
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(h) = Hash256::from_hex(s) {
            let hex_out = h.to_hex();
            let h2 = Hash256::from_hex(&hex_out).expect("roundtrip must succeed");
            assert_eq!(h, h2, "roundtrip mismatch");
        }
    }
});
