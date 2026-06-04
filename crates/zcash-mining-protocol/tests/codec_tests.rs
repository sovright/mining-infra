use zcash_mining_protocol::codec::{decode_message, encode_message};
use zcash_mining_protocol::messages::{NewEquihashJob, SubmitEquihashShare};

#[test]
fn test_new_equihash_job_roundtrip() {
    let job = NewEquihashJob {
        channel_id: 1,
        job_id: 42,
        future_job: false,
        version: 5,
        prev_hash: [0xaa; 32],
        merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32],
        nonce_1: vec![0x01, 0x02, 0x03, 0x04],
        nonce_2_len: 28,
        time: 1700000000,
        bits: 0x1d00ffff,
        target: [0x00; 32],
        clean_jobs: true,
    };

    let encoded = encode_message(&job).unwrap();
    let decoded: NewEquihashJob = decode_message(&encoded).unwrap();

    assert_eq!(job, decoded);
}

#[test]
fn test_submit_share_roundtrip() {
    let share = SubmitEquihashShare {
        channel_id: 1,
        sequence_number: 100,
        job_id: 42,
        nonce_2: vec![0xff; 28],
        time: 1700000001,
        solution: [0x12; 1344],
    };

    let encoded = encode_message(&share).unwrap();
    let decoded: SubmitEquihashShare = decode_message(&encoded).unwrap();

    assert_eq!(share, decoded);
}
