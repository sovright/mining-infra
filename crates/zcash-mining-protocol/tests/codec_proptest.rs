//! Property-based roundtrip tests for the mining protocol codec.
//!
//! Each test generates arbitrary message instances and verifies that
//! encode -> decode produces the original message.

use proptest::prelude::*;
use zcash_mining_protocol::codec::{
    decode_new_equihash_job, decode_set_target, decode_submit_share,
    decode_submit_shares_response, encode_new_equihash_job, encode_set_target,
    encode_submit_share, encode_submit_shares_response, Decodable, Encodable,
};
use zcash_mining_protocol::messages::{
    NewEquihashJob, RejectReason, SetTarget, ShareResult, SubmitEquihashShare,
    SubmitSharesResponse,
};

/// Strategy for generating a valid NewEquihashJob.
/// The key constraint is nonce_1.len() + nonce_2_len == 32.
fn arb_new_equihash_job() -> impl Strategy<Value = NewEquihashJob> {
    // Split into two sub-tuples to stay within proptest's 12-element tuple limit.
    // First pick nonce_1 length so we can derive nonce_2_len = 32 - n1_len.
    (0u8..=32u8).prop_flat_map(|n1_len| {
        let n2_len = 32 - n1_len;
        (
            // Group A: scalar fields
            (
                any::<u32>(),  // channel_id
                any::<u32>(),  // job_id
                any::<bool>(), // future_job
                any::<u32>(),  // version
                any::<u32>(),  // time
                any::<u32>(),  // bits
                any::<bool>(), // clean_jobs
            ),
            // Group B: byte-array and variable-length fields
            (
                any::<[u8; 32]>(), // prev_hash
                any::<[u8; 32]>(), // merkle_root
                any::<[u8; 32]>(), // block_commitments
                proptest::collection::vec(any::<u8>(), n1_len as usize), // nonce_1
                Just(n2_len),      // nonce_2_len
                any::<[u8; 32]>(), // target
            ),
        )
    })
    .prop_map(
        |((channel_id, job_id, future_job, version, time, bits, clean_jobs),
          (prev_hash, merkle_root, block_commitments, nonce_1, nonce_2_len, target))| {
            NewEquihashJob {
                channel_id,
                job_id,
                future_job,
                version,
                prev_hash,
                merkle_root,
                block_commitments,
                nonce_1,
                nonce_2_len,
                time,
                bits,
                target,
                clean_jobs,
            }
        },
    )
}

/// Strategy for generating a valid SubmitEquihashShare.
/// nonce_2 can be 0..=32 bytes; solution is always 1344 bytes.
fn arb_submit_equihash_share() -> impl Strategy<Value = SubmitEquihashShare> {
    (
        any::<u32>(),                                           // channel_id
        any::<u32>(),                                           // sequence_number
        any::<u32>(),                                           // job_id
        proptest::collection::vec(any::<u8>(), 0..=32usize),    // nonce_2
        any::<u32>(),                                           // time
        proptest::collection::vec(any::<u8>(), 1344..=1344usize), // solution bytes
    )
        .prop_map(|(channel_id, sequence_number, job_id, nonce_2, time, sol_vec)| {
            let mut solution = [0u8; 1344];
            solution.copy_from_slice(&sol_vec);
            SubmitEquihashShare {
                channel_id,
                sequence_number,
                job_id,
                nonce_2,
                time,
                solution,
            }
        })
}

/// Strategy for generating a RejectReason.
/// The Other variant's string is limited to 255 ASCII bytes to survive the
/// encode truncation and UTF-8 roundtrip.
fn arb_reject_reason() -> impl Strategy<Value = RejectReason> {
    prop_oneof![
        Just(RejectReason::StaleJob),
        Just(RejectReason::Duplicate),
        Just(RejectReason::InvalidSolution),
        Just(RejectReason::LowDifficulty),
        // Only ASCII to guarantee UTF-8 validity; max 255 bytes to avoid truncation.
        "[a-zA-Z0-9 _]{0,255}".prop_map(RejectReason::Other),
    ]
}

/// Strategy for generating a SubmitSharesResponse.
fn arb_submit_shares_response() -> impl Strategy<Value = SubmitSharesResponse> {
    (
        any::<u32>(), // channel_id
        any::<u32>(), // sequence_number
        prop_oneof![
            Just(ShareResult::Accepted),
            arb_reject_reason().prop_map(ShareResult::Rejected),
        ],
    )
        .prop_map(|(channel_id, sequence_number, result)| SubmitSharesResponse {
            channel_id,
            sequence_number,
            result,
        })
}

/// Strategy for generating a SetTarget.
fn arb_set_target() -> impl Strategy<Value = SetTarget> {
    (any::<u32>(), any::<[u8; 32]>()).prop_map(|(channel_id, target)| SetTarget {
        channel_id,
        target,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn roundtrip_new_equihash_job(job in arb_new_equihash_job()) {
        let encoded = encode_new_equihash_job(&job).expect("encode should succeed");
        let decoded = decode_new_equihash_job(&encoded).expect("decode should succeed");
        prop_assert_eq!(&job, &decoded);
    }

    #[test]
    fn roundtrip_new_equihash_job_trait(job in arb_new_equihash_job()) {
        let encoded = job.encode().expect("trait encode should succeed");
        let decoded = NewEquihashJob::decode(&encoded).expect("trait decode should succeed");
        prop_assert_eq!(&job, &decoded);
    }

    #[test]
    fn roundtrip_submit_equihash_share(share in arb_submit_equihash_share()) {
        let encoded = encode_submit_share(&share).expect("encode should succeed");
        let decoded = decode_submit_share(&encoded).expect("decode should succeed");
        prop_assert_eq!(&share, &decoded);
    }

    #[test]
    fn roundtrip_submit_equihash_share_trait(share in arb_submit_equihash_share()) {
        let encoded = share.encode().expect("trait encode should succeed");
        let decoded = SubmitEquihashShare::decode(&encoded).expect("trait decode should succeed");
        prop_assert_eq!(&share, &decoded);
    }

    #[test]
    fn roundtrip_submit_shares_response(resp in arb_submit_shares_response()) {
        let encoded = encode_submit_shares_response(&resp).expect("encode should succeed");
        let decoded = decode_submit_shares_response(&encoded).expect("decode should succeed");
        prop_assert_eq!(&resp, &decoded);
    }

    #[test]
    fn roundtrip_submit_shares_response_trait(resp in arb_submit_shares_response()) {
        let encoded = resp.encode().expect("trait encode should succeed");
        let decoded = SubmitSharesResponse::decode(&encoded).expect("trait decode should succeed");
        prop_assert_eq!(&resp, &decoded);
    }

    #[test]
    fn roundtrip_set_target(msg in arb_set_target()) {
        let encoded = encode_set_target(&msg).expect("encode should succeed");
        let decoded = decode_set_target(&encoded).expect("decode should succeed");
        prop_assert_eq!(&msg, &decoded);
    }

    #[test]
    fn roundtrip_set_target_trait(msg in arb_set_target()) {
        let encoded = msg.encode().expect("trait encode should succeed");
        let decoded = SetTarget::decode(&encoded).expect("trait decode should succeed");
        prop_assert_eq!(&msg, &decoded);
    }
}
