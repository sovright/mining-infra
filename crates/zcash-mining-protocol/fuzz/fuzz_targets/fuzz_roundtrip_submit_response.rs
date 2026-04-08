#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use zcash_mining_protocol::codec::{encode_submit_shares_response, decode_submit_shares_response};
use zcash_mining_protocol::messages::{SubmitSharesResponse, ShareResult, RejectReason};

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(mut resp) = SubmitSharesResponse::arbitrary(&mut u) else { return };

    // The encoder truncates Other messages to 255 bytes.
    // Normalize before roundtrip comparison.
    if let ShareResult::Rejected(RejectReason::Other(ref mut msg)) = resp.result {
        let max = 255;
        if msg.len() > max {
            let truncated = &msg.as_bytes()[..max];
            match std::str::from_utf8(truncated) {
                Ok(s) => *msg = s.to_string(),
                Err(e) => *msg = std::str::from_utf8(&truncated[..e.valid_up_to()])
                    .unwrap()
                    .to_string(),
            }
        }
    }

    let encoded1 = match encode_submit_shares_response(&resp) {
        Ok(e) => e,
        Err(_) => return,
    };
    let decoded1 = decode_submit_shares_response(&encoded1)
        .expect("decode must succeed for encoder output");

    assert_eq!(resp, decoded1, "first roundtrip mismatch");

    // Double roundtrip: re-encode and re-decode to catch asymmetric codec bugs
    let encoded2 = encode_submit_shares_response(&decoded1)
        .expect("re-encode must succeed for decoded value");
    assert_eq!(encoded1, encoded2, "double-roundtrip encoded mismatch");

    let decoded2 = decode_submit_shares_response(&encoded2)
        .expect("re-decode must succeed for re-encoded output");
    assert_eq!(decoded1, decoded2, "double-roundtrip decoded mismatch");
});
