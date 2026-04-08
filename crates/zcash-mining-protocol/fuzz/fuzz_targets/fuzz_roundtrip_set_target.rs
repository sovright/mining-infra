#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use zcash_mining_protocol::codec::{encode_set_target, decode_set_target};
use zcash_mining_protocol::messages::SetTarget;

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(msg) = SetTarget::arbitrary(&mut u) else { return };

    let encoded1 = match encode_set_target(&msg) {
        Ok(e) => e,
        Err(_) => return,
    };
    let decoded1 = decode_set_target(&encoded1)
        .expect("decode must succeed for encoder output");

    assert_eq!(msg, decoded1, "first roundtrip mismatch");

    // Double roundtrip: re-encode and re-decode to catch asymmetric codec bugs
    let encoded2 = encode_set_target(&decoded1)
        .expect("re-encode must succeed for decoded value");
    assert_eq!(encoded1, encoded2, "double-roundtrip encoded mismatch");

    let decoded2 = decode_set_target(&encoded2)
        .expect("re-decode must succeed for re-encoded output");
    assert_eq!(decoded1, decoded2, "double-roundtrip decoded mismatch");
});
