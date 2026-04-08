//! One-shot test to generate seed corpus files for fuzzing.
//! Run: cargo test -p zcash-jd-server --test generate_corpus -- --ignored

use zcash_jd_server::*;
use std::fs;

#[test]
#[ignore]
fn generate_fuzz_corpus() {
    let corpus_base = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus");

    // AllocateMiningJobToken
    let dir = format!("{}/fuzz_decode_allocate_token", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let msg = AllocateMiningJobToken::with_mode(1, "test-miner", JobDeclarationMode::CoinbaseOnly);
    fs::write(format!("{}/valid", dir), encode_allocate_token(&msg).unwrap()).unwrap();

    // AllocateMiningJobTokenSuccess
    let dir = format!("{}/fuzz_decode_allocate_token_success", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let msg = AllocateMiningJobTokenSuccess {
        request_id: 1,
        mining_job_token: vec![0x42; 16],
        coinbase_output: vec![0x76, 0xa9, 0x14],
        coinbase_output_max_additional_size: 256,
        async_mining_allowed: true,
        granted_mode: JobDeclarationMode::CoinbaseOnly,
    };
    fs::write(format!("{}/valid", dir), encode_allocate_token_success(&msg).unwrap()).unwrap();

    // SetCustomMiningJob
    let dir = format!("{}/fuzz_decode_set_custom_job", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let msg = SetCustomMiningJob {
        channel_id: 1, request_id: 1, mining_job_token: vec![0x42; 16],
        version: 5, prev_hash: [0xaa; 32], merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32], coinbase_tx: vec![0x01; 100],
        time: 1700000000, bits: 0x1d00ffff,
    };
    fs::write(format!("{}/valid", dir), encode_set_custom_job(&msg).unwrap()).unwrap();

    // SetCustomMiningJobSuccess
    let dir = format!("{}/fuzz_decode_set_custom_job_success", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let msg = SetCustomMiningJobSuccess::new(1, 1, 42);
    fs::write(format!("{}/valid", dir), encode_set_custom_job_success(&msg).unwrap()).unwrap();

    // SetCustomMiningJobError
    let dir = format!("{}/fuzz_decode_set_custom_job_error", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let msg = SetCustomMiningJobError::new(1, 1, SetCustomMiningJobErrorCode::InvalidToken, "bad token");
    fs::write(format!("{}/valid", dir), encode_set_custom_job_error(&msg).unwrap()).unwrap();

    // PushSolution
    let dir = format!("{}/fuzz_decode_push_solution", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let msg = PushSolution::new(1, 42, 5, 1700000000, [0x11; 32], [0x22; 1344]);
    fs::write(format!("{}/valid", dir), encode_push_solution(&msg).unwrap()).unwrap();

    // SetFullTemplateJob
    let dir = format!("{}/fuzz_decode_set_full_template", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let msg = SetFullTemplateJob {
        channel_id: 1, request_id: 1, mining_job_token: vec![0x42; 16],
        version: 5, prev_hash: [0xaa; 32], merkle_root: [0xbb; 32],
        block_commitments: [0xcc; 32], coinbase_tx: vec![0x01; 100],
        time: 1700000000, bits: 0x1d00ffff,
        tx_short_ids: vec![[0xdd; 32]], tx_data: vec![vec![0x01; 50]],
    };
    fs::write(format!("{}/valid", dir), encode_set_full_template_job(&msg).unwrap()).unwrap();

    // SetFullTemplateJobSuccess
    let dir = format!("{}/fuzz_decode_set_full_template_success", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let msg = SetFullTemplateJobSuccess::new(1, 1, 42);
    fs::write(format!("{}/valid", dir), encode_set_full_template_job_success(&msg).unwrap()).unwrap();

    // SetFullTemplateJobError
    let dir = format!("{}/fuzz_decode_set_full_template_error", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let msg = SetFullTemplateJobError::new(1, 1, SetFullTemplateJobErrorCode::InvalidToken, "bad token");
    fs::write(format!("{}/valid", dir), encode_set_full_template_job_error(&msg).unwrap()).unwrap();

    // GetMissingTransactions
    let dir = format!("{}/fuzz_decode_get_missing_tx", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let msg = GetMissingTransactions::new(1, 1, vec![[0xee; 32]]);
    fs::write(format!("{}/valid", dir), encode_get_missing_transactions(&msg).unwrap()).unwrap();

    // ProvideMissingTransactions
    let dir = format!("{}/fuzz_decode_provide_missing_tx", corpus_base);
    fs::create_dir_all(&dir).unwrap();
    let msg = ProvideMissingTransactions::new(1, 1, vec![vec![0x01; 50]]);
    fs::write(format!("{}/valid", dir), encode_provide_missing_transactions(&msg).unwrap()).unwrap();

    println!("Corpus files generated in {}", corpus_base);
}
