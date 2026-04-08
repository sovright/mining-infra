#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use zcash_mining_protocol::codec::{encode_new_equihash_job, decode_new_equihash_job};
use zcash_mining_protocol::messages::NewEquihashJob;

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(mut job) = NewEquihashJob::arbitrary(&mut u) else { return };

    // Constrain: nonce_1.len() + nonce_2_len must == 32
    if job.nonce_1.len() > 32 {
        job.nonce_1.truncate(32);
    }
    job.nonce_2_len = (32 - job.nonce_1.len()) as u8;

    let encoded1 = match encode_new_equihash_job(&job) {
        Ok(e) => e,
        Err(_) => return,
    };
    let decoded1 = decode_new_equihash_job(&encoded1)
        .expect("decode must succeed for encoder output");

    assert_eq!(job, decoded1, "first roundtrip mismatch");

    // Double roundtrip: re-encode and re-decode to catch asymmetric codec bugs
    let encoded2 = encode_new_equihash_job(&decoded1)
        .expect("re-encode must succeed for decoded value");
    assert_eq!(encoded1, encoded2, "double-roundtrip encoded mismatch");

    let decoded2 = decode_new_equihash_job(&encoded2)
        .expect("re-decode must succeed for re-encoded output");
    assert_eq!(decoded1, decoded2, "double-roundtrip decoded mismatch");
});
