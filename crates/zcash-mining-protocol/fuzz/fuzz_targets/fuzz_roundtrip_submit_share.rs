#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use zcash_mining_protocol::codec::{encode_submit_share, decode_submit_share};
use zcash_mining_protocol::messages::SubmitEquihashShare;

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(mut share) = SubmitEquihashShare::arbitrary(&mut u) else { return };

    // Constrain nonce_2 to valid range
    if share.nonce_2.len() > 32 {
        share.nonce_2.truncate(32);
    }

    let encoded1 = match encode_submit_share(&share) {
        Ok(e) => e,
        Err(_) => return,
    };
    let decoded1 = decode_submit_share(&encoded1)
        .expect("decode must succeed for encoder output");

    assert_eq!(share, decoded1, "first roundtrip mismatch");

    // Double roundtrip: re-encode and re-decode to catch asymmetric codec bugs
    let encoded2 = encode_submit_share(&decoded1)
        .expect("re-encode must succeed for decoded value");
    assert_eq!(encoded1, encoded2, "double-roundtrip encoded mismatch");

    let decoded2 = decode_submit_share(&encoded2)
        .expect("re-decode must succeed for re-encoded output");
    assert_eq!(decoded1, decoded2, "double-roundtrip decoded mismatch");
});
