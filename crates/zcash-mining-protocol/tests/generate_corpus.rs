//! One-shot test to generate seed corpus files for fuzzing.
//! Run: cargo test -p zcash-mining-protocol --test generate_corpus -- --ignored

use zcash_mining_protocol::codec::*;
use zcash_mining_protocol::messages::*;
use std::fs;

#[test]
#[ignore]
fn generate_fuzz_corpus() {
    let corpus_base = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus");

    // Frame decode corpus
    let dir = format!("{}/fuzz_frame_decode", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let frame = MessageFrame { extension_type: 0, msg_type: 0x20, length: 100 };
    fs::write(format!("{}/valid_frame", dir), frame.encode()).unwrap();
    fs::write(format!("{}/empty", dir), &[] as &[u8]).unwrap();
    fs::write(format!("{}/short", dir), &[0x00, 0x00]).unwrap();

    // NewEquihashJob corpus
    let dir = format!("{}/fuzz_decode_new_job", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let job = NewEquihashJob {
        channel_id: 1, job_id: 42, future_job: false, version: 5,
        prev_hash: [0xaa; 32], merkle_root: [0xbb; 32], block_commitments: [0xcc; 32],
        nonce_1: vec![0x01, 0x02, 0x03, 0x04], nonce_2_len: 28,
        time: 1700000000, bits: 0x1d00ffff, target: [0x00; 32], clean_jobs: true,
    };
    fs::write(format!("{}/valid_job", dir), encode_new_equihash_job(&job).unwrap()).unwrap();

    // SubmitEquihashShare corpus
    let dir = format!("{}/fuzz_decode_submit_share", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let share = SubmitEquihashShare {
        channel_id: 1, sequence_number: 100, job_id: 42,
        nonce_2: vec![0xff; 28], time: 1700000001, solution: [0x12; 1344],
    };
    fs::write(format!("{}/valid_share", dir), encode_submit_share(&share).unwrap()).unwrap();

    // SubmitSharesResponse corpus
    let dir = format!("{}/fuzz_decode_submit_response", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let accepted = SubmitSharesResponse {
        channel_id: 42, sequence_number: 100, result: ShareResult::Accepted,
    };
    fs::write(format!("{}/accepted", dir), encode_submit_shares_response(&accepted).unwrap()).unwrap();
    let rejected = SubmitSharesResponse {
        channel_id: 1, sequence_number: 5,
        result: ShareResult::Rejected(RejectReason::StaleJob),
    };
    fs::write(format!("{}/rejected_stale", dir), encode_submit_shares_response(&rejected).unwrap()).unwrap();
    let other = SubmitSharesResponse {
        channel_id: 3, sequence_number: 77,
        result: ShareResult::Rejected(RejectReason::Other("custom error".to_string())),
    };
    fs::write(format!("{}/rejected_other", dir), encode_submit_shares_response(&other).unwrap()).unwrap();

    // SetTarget corpus
    let dir = format!("{}/fuzz_decode_set_target", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let target = SetTarget { channel_id: 99, target: [0xab; 32] };
    fs::write(format!("{}/valid_target", dir), encode_set_target(&target).unwrap()).unwrap();

    // Roundtrip targets share the same corpus as their decode counterparts
    for (src, dst) in [
        ("fuzz_decode_new_job", "fuzz_roundtrip_new_job"),
        ("fuzz_decode_submit_share", "fuzz_roundtrip_submit_share"),
        ("fuzz_decode_submit_response", "fuzz_roundtrip_submit_response"),
        ("fuzz_decode_set_target", "fuzz_roundtrip_set_target"),
    ] {
        let src_dir = format!("{}/{}", corpus_base, src);
        let dst_dir = format!("{}/{}", corpus_base, dst);
        fs::create_dir_all(&dst_dir).unwrap();
        for entry in fs::read_dir(&src_dir).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), format!("{}/{}", dst_dir, entry.file_name().to_str().unwrap())).unwrap();
        }
    }

    println!("Corpus files generated in {}", corpus_base);
}
