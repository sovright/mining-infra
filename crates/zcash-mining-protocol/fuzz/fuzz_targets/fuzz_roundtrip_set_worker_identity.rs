#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zcash_mining_protocol::codec::{decode_set_worker_identity, encode_set_worker_identity};
use zcash_mining_protocol::messages::SetWorkerIdentity;

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(msg) = SetWorkerIdentity::arbitrary(&mut u) else {
        return;
    };

    let encoded1 = match encode_set_worker_identity(&msg) {
        Ok(e) => e,
        // Names outside 1-255 bytes are rejected by design.
        Err(_) => return,
    };
    let decoded1 =
        decode_set_worker_identity(&encoded1).expect("decode must succeed for encoder output");

    assert_eq!(msg, decoded1, "first roundtrip mismatch");

    // Double roundtrip: re-encode and re-decode to catch asymmetric codec bugs
    let encoded2 = encode_set_worker_identity(&decoded1)
        .expect("re-encode must succeed for decoded value");
    assert_eq!(encoded1, encoded2, "double-roundtrip encoded mismatch");

    let decoded2 = decode_set_worker_identity(&encoded2)
        .expect("re-decode must succeed for re-encoded output");
    assert_eq!(decoded1, decoded2, "double-roundtrip decoded mismatch");
});
