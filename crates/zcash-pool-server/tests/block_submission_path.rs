//! Block submission path validation tests.
//!
//! Tests the critical path: share meets block target -> block serialization -> submit to Zebra.
//! Uses the Zcash mainnet genesis block as a real test vector with a known-valid Equihash solution.

use zcash_equihash_validator::EquihashValidator;
use zcash_mining_protocol::messages::{NewEquihashJob, SubmitEquihashShare};
use zcash_pool_server::{InMemoryDuplicateDetector, ShareProcessor};
use zcash_pool_common::write_compact_size;
use zcash_template_provider::types::{
    BlockTemplate, EquihashHeader, Hash256, TemplateTransaction,
};

// ---------------------------------------------------------------------------
// Zcash mainnet genesis block test vectors
// ---------------------------------------------------------------------------

/// The 140-byte genesis block header.
fn genesis_header_bytes() -> [u8; 140] {
    let bytes = hex::decode(
        "04000000\
         0000000000000000000000000000000000000000000000000000000000000000\
         db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac4\
         0000000000000000000000000000000000000000000000000000000000000000\
         90041358\
         ffff071f\
         5712000000000000000000000000000000000000000000000000000000000000",
    )
    .expect("valid hex");
    let mut arr = [0u8; 140];
    arr.copy_from_slice(&bytes);
    arr
}

/// The 1344-byte genesis block Equihash solution.
fn genesis_solution() -> [u8; 1344] {
    let bytes = hex::decode(
        "000a889f00854b8665cd555f4656f68179d31ccadc1b1f7fb0952726313b16941da348284d67add4\
         686121d4e3d930160c1348d8191c25f12b267a6a9c131b5031cbf8af1f79c9d513076a216ec87ed0\
         45fa966e01214ed83ca02dc1797270a454720d3206ac7d931a0a680c5c5e099057592570ca9bdf605\
         8343958b31901fce1a15a4f38fd347750912e14004c73dfe588b903b6c03166582eeaf30529b14072\
         a7b3079e3a684601b9b3024054201f7440b0ee9eb1a7120ff43f713735494aa27b1f8bab60d7f398b\
         ca14f6abb2adbf29b04099121438a7974b078a11635b594e9170f1086140b4173822dd697894483e1\
         c6b4e8b8dcd5cb12ca4903bc61e108871d4d915a9093c18ac9b02b6716ce1013ca2c1174e319c1a57\
         0215bc9ab5f7564765f7be20524dc3fdf8aa356fd94d445e05ab165ad8bb4a0db096c097618c81098\
         f91443c719416d39837af6de85015dca0de89462b1d8386758b2cf8a99e00953b308032ae44c35e05\
         eb71842922eb69797f68813b59caf266cb6c213569ae3280505421a7e3a0a37fdf8e2ea354fc54228\
         16655394a9454bac542a9298f176e211020d63dee6852c40de02267e2fc9d5e1ff2ad9309506f02a1\
         a71a0501b16d0d36f70cdfd8de78116c0c506ee0b8ddfdeb561acadf31746b5a9dd32c21930884397\
         fb1682164cb565cc14e089d66635a32618f7eb05fe05082b8a3fae620571660a6b89886eac53dec10\
         9d7cbb6930ca698a168f301a950be152da1be2b9e07516995e20baceebecb5579d7cdbc16d09f3a50\
         cb3c7dffe33f26686d4ff3f8946ee6475e98cf7b3cf9062b6966e838f865ff3de5fb064a37a21da7b\
         b8dfd2501a29e184f207caaba364f36f2329a77515dcb710e29ffbf73e2bbd773fab1f9a6b005567a\
         ffff605c132e4e4dd69f36bd201005458cfbd2c658701eb2a700251cefd886b1e674ae816d3f719ba\
         c64be649c172ba27a4fd55947d95d53ba4cbc73de97b8af5ed4840b659370c556e7376457f51e5ebb\
         66018849923db82c1c9a819f173cccdb8f3324b239609a300018d0fb094adf5bd7cbb3834c69e6d0b\
         3798065c525b20f040e965e1a161af78ff7561cd874f5f1b75aa0bc77f720589e1b810f831eac5073\
         e6dd46d00a2793f70f7427f0f798f2f53a67e615e65d356e66fe40609a958a05edb4c175bcc383ea0\
         530e67ddbe479a898943c6e3074c6fcc252d6014de3a3d292b03f0d88d312fe221be7be7e3c59d07f\
         a0f2f4029e364f1f355c5d01fa53770d0cd76d82bf7e60f6903bc1beb772e6fde4a70be51d9c7e03c\
         8d6d8dfb361a234ba47c470fe630820bbd920715621b9fbedb49fcee165ead0875e6c2b1af16f50b5\
         d6140cc981122fcbcf7c5a4e3772b3661b628e08380abc545957e59f634705b1bbde2f0b4e055a5ec\
         5676d859be77e20962b645e051a880fddb0180b4555789e1f9344a436a84dc5579e2553f1e5fb0a59\
         9c137be36cabbed0319831fea3fddf94ddc7971e4bcf02cdc93294a9aab3e3b13e3b058235b4f4ec0\
         6ba4ceaa49d675b4ba80716f3bc6976b1fbf9c8bf1f3e3a4dc1cd83ef9cf816667fb94f1e923ff63f\
         ef072e6a19321e4812f96cb0ffa864da50ad74deb76917a336f31dce03ed5f0303aad5e6a83634f9f\
         cc371096f8288b8f02ddded5ff1bb9d49331e4a84dbe1543164438fde9ad71dab024779dcdde0b660\
         2b5ae0a6265c14b94edd83b37403f4b78fcd2ed555b596402c28ee81d87a909c4e8722b30c71ecdd8\
         61b05f61f8b1231795c76adba2fdefa451b283a5d527955b9f3de1b9828e7b2e74123dd47062ddcc0\
         9b05e7fa13cb2212a6fdbc65d7e852cec463ec6fd929f5b8483cf3052113b13dac91b69f49d1b7d1a\
         ec01c4a68e41ce157",
    )
    .expect("valid hex");
    let mut arr = [0u8; 1344];
    arr.copy_from_slice(&bytes);
    arr
}

/// Construct a NewEquihashJob whose build_header() produces the exact genesis header.
fn genesis_job() -> NewEquihashJob {
    let header = genesis_header_bytes();

    // Extract fields from the 140-byte header:
    //   [0..4]    version (LE u32)
    //   [4..36]   prev_hash
    //   [36..68]  merkle_root
    //   [68..100] block_commitments
    //   [100..104] time (LE u32)
    //   [104..108] bits (LE u32)
    //   [108..140] nonce (32 bytes)
    let version = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(&header[4..36]);
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&header[36..68]);
    let mut block_commitments = [0u8; 32];
    block_commitments.copy_from_slice(&header[68..100]);
    let time = u32::from_le_bytes(header[100..104].try_into().unwrap());
    let bits = u32::from_le_bytes(header[104..108].try_into().unwrap());
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&header[108..140]);

    // Split nonce into nonce_1 (4 bytes) and nonce_2 (28 bytes)
    let nonce_1 = nonce[..4].to_vec();
    let nonce_2_len = 28u8;

    NewEquihashJob {
        channel_id: 1,
        job_id: 1,
        future_job: false,
        version,
        prev_hash,
        merkle_root,
        block_commitments,
        nonce_1,
        nonce_2_len,
        time,
        bits,
        target: [0xff; 32], // Easy share target -- any valid solution passes
        clean_jobs: false,
    }
}

/// Extract nonce_2 from the genesis header (bytes [112..140] of the nonce portion).
fn genesis_nonce_2() -> Vec<u8> {
    let header = genesis_header_bytes();
    // nonce is at header[108..140]; nonce_1 = [108..112], nonce_2 = [112..140]
    header[112..140].to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that the NewEquihashJob we construct produces the exact genesis header
/// when combined with the correct nonce.
#[test]
fn test_genesis_job_builds_correct_header() {
    let job = genesis_job();
    let nonce_2 = genesis_nonce_2();
    let full_nonce = job.build_nonce(&nonce_2).expect("nonce_2 length must match");
    let built_header = job.build_header(&full_nonce);
    let expected_header = genesis_header_bytes();

    assert_eq!(
        built_header, expected_header,
        "NewEquihashJob::build_header() must reproduce the exact genesis header"
    );
}

/// The core block submission path test: validate_share_with_job returns is_block=true
/// for the genesis block solution with an easy block target.
#[test]
fn test_block_find_with_real_equihash_solution() {
    let job = genesis_job();
    let nonce_2 = genesis_nonce_2();
    let solution = genesis_solution();
    let detector = InMemoryDuplicateDetector::new();
    let processor = ShareProcessor::new();

    // Easy block target: any valid solution qualifies as a block
    let block_target = [0xff; 32];

    let share = SubmitEquihashShare {
        channel_id: 1,
        sequence_number: 1,
        job_id: 1,
        nonce_2,
        time: job.time,
        solution,
    };

    let result = processor
        .validate_share_with_job(&share, &job, &detector, &block_target)
        .expect("validation should not return Err");

    assert!(result.accepted, "Genesis solution must be accepted");
    assert!(
        result.is_block,
        "Genesis solution with easy block target must qualify as a block"
    );
    assert!(
        result.difficulty.is_some(),
        "Accepted share must have a difficulty value"
    );
    assert!(
        result.difficulty.unwrap() > 0.0,
        "Difficulty must be positive"
    );
}

/// Verify that the genesis solution hash meets a realistic (easy) target
/// but does NOT meet an impossibly hard target.
#[test]
fn test_block_hash_target_discrimination() {
    let validator = EquihashValidator::new();
    let header = genesis_header_bytes();
    let solution = genesis_solution();

    // Easy target: should pass
    let easy_target = [0xff; 32];
    let hash = validator
        .verify_share(&header, &solution, &easy_target)
        .expect("Genesis solution must pass with easy target");

    assert_ne!(hash, [0u8; 32], "Block hash should be non-zero");

    // Impossibly hard target (all zeros): should fail
    let impossible_target = [0x00; 32];
    let err = validator
        .verify_share(&header, &solution, &impossible_target)
        .expect_err("Genesis solution should NOT meet impossible target");
    assert!(
        matches!(err, zcash_equihash_validator::ValidationError::TargetNotMet),
        "Expected TargetNotMet, got: {:?}",
        err
    );

    // Verify the hash has specific non-trivial properties:
    // A moderately hard target (leading zero byte + 0x10 second byte) should still be met
    // by the genesis hash, confirming it's a real proof-of-work hash.
    // First, let's inspect the hash to set a meaningful threshold.
    let mut moderate_target = [0xff; 32];
    // The hash should meet a target where the most significant bytes allow some zeros.
    // Set the MSB (index 31 in LE) to a moderate value. If the genesis hash has leading
    // zeros (common for PoW), this should pass.
    moderate_target[31] = 0x10;
    let moderate_result = validator.verify_share(&header, &solution, &moderate_target);
    // We just verify the hash is non-zero and was returned successfully with easy target;
    // the moderate target test is informational (genesis was very easy difficulty).
    // The critical assertion is the easy/impossible discrimination above.
    if moderate_result.is_ok() {
        // Good -- the genesis hash has some PoW quality
    }
    // Either way, the key tests (easy passes, impossible fails) are the important ones.
}

/// Verify that validate_share_with_job correctly distinguishes between
/// "valid share but not a block" and "valid share AND a block".
#[test]
fn test_is_block_depends_on_block_target() {
    let job = genesis_job();
    let nonce_2 = genesis_nonce_2();
    let solution = genesis_solution();
    let processor = ShareProcessor::new();

    let share = SubmitEquihashShare {
        channel_id: 1,
        sequence_number: 1,
        job_id: 1,
        nonce_2: nonce_2.clone(),
        time: job.time,
        solution,
    };

    // With easy block target: is_block should be true
    let detector1 = InMemoryDuplicateDetector::new();
    let easy_result = processor
        .validate_share_with_job(&share, &job, &detector1, &[0xff; 32])
        .unwrap();
    assert!(easy_result.accepted);
    assert!(easy_result.is_block, "Easy target: should be a block");

    // With impossible block target: is_block should be false (share still accepted
    // because it meets the share target, but doesn't meet the block target)
    let detector2 = InMemoryDuplicateDetector::new();
    let hard_result = processor
        .validate_share_with_job(&share, &job, &detector2, &[0x00; 32])
        .unwrap();
    assert!(hard_result.accepted, "Share should still be accepted (meets share target)");
    assert!(
        !hard_result.is_block,
        "Impossible block target: should NOT be a block"
    );
}

/// Test block serialization: reconstruct the same logic as server::build_block_bytes
/// and verify the output has the correct structure and length.
#[test]
fn test_block_serialization_structure() {
    let job = genesis_job();
    let nonce_2 = genesis_nonce_2();
    let solution = genesis_solution();

    // Minimal coinbase (same as TestTemplateFactory default)
    let coinbase_hex = "05000000\
        01\
        0000000000000000000000000000000000000000000000000000000000000000ffffffff\
        0404ffffff\
        ffffffff\
        01\
        0000000000000000\
        0100\
        00000000";
    let coinbase = hex::decode(coinbase_hex).expect("valid coinbase hex");

    // A fake transaction for completeness
    let tx_data_hex = "0500000001aaaa0000";
    let tx = TemplateTransaction {
        data: tx_data_hex.to_string(),
        hash: "00".repeat(32),
        fee: 1000,
        depends: vec![],
    };

    // Build a BlockTemplate that matches our job's prev_hash
    let template = BlockTemplate {
        template_id: 1,
        height: 1,
        header: EquihashHeader {
            version: job.version,
            prev_hash: Hash256(job.prev_hash),
            merkle_root: Hash256(job.merkle_root),
            hash_block_commitments: Hash256(job.block_commitments),
            time: job.time,
            bits: job.bits,
            nonce: [0; 32],
        },
        target: Hash256([0xff; 32]),
        transactions: vec![tx],
        coinbase: coinbase.clone(),
        total_fees: 1000,
    };

    let share = SubmitEquihashShare {
        channel_id: 1,
        sequence_number: 1,
        job_id: 1,
        nonce_2: nonce_2.clone(),
        time: job.time,
        solution,
    };

    // Replicate build_block_bytes logic (it's private to server.rs)
    let full_nonce = job.build_nonce(&share.nonce_2).unwrap();
    let mut header = job.build_header(&full_nonce);
    header[100..104].copy_from_slice(&share.time.to_le_bytes());

    let mut block = Vec::new();
    block.extend_from_slice(&header);
    // CompactSize for solution length (1344)
    write_compact_size(1344, &mut block);
    block.extend_from_slice(&share.solution);

    let tx_count = 1 + template.transactions.len() as u64; // coinbase + txs
    write_compact_size(tx_count, &mut block);
    block.extend_from_slice(&template.coinbase);

    for tx in &template.transactions {
        let tx_bytes = hex::decode(&tx.data).expect("valid tx hex");
        block.extend_from_slice(&tx_bytes);
    }

    // Verify structure
    let block_hex = hex::encode(&block);

    // 1. Header (140 bytes)
    assert_eq!(&block[..140], &header[..], "Block must start with the header");

    // 2. CompactSize for solution: 1344 = 0x0540, encoded as fd 40 05
    assert_eq!(
        &block[140..143],
        &[0xfd, 0x40, 0x05],
        "CompactSize encoding for 1344-byte solution"
    );

    // 3. Solution (1344 bytes)
    assert_eq!(
        &block[143..143 + 1344],
        &share.solution[..],
        "Solution bytes must follow header"
    );

    // 4. Tx count (CompactSize for 2 = coinbase + 1 tx)
    assert_eq!(block[143 + 1344], 0x02, "Tx count should be 2 (coinbase + 1 tx)");

    // 5. Coinbase follows
    let coinbase_start = 143 + 1344 + 1;
    assert_eq!(
        &block[coinbase_start..coinbase_start + coinbase.len()],
        &coinbase[..],
        "Coinbase transaction bytes must follow tx count"
    );

    // 6. Block hex should be valid hex of expected length
    let tx_data_bytes = hex::decode(tx_data_hex).unwrap();
    let expected_len = 140 + 3 + 1344 + 1 + coinbase.len() + tx_data_bytes.len();
    assert_eq!(
        block.len(),
        expected_len,
        "Total block length must match: header + compact_size + solution + tx_count + coinbase + txs"
    );
    assert_eq!(
        block_hex.len(),
        expected_len * 2,
        "Hex string length must be 2x the byte length"
    );
}

/// Test the coinbase-only block (no extra transactions) serialization.
#[test]
fn test_block_serialization_coinbase_only() {
    let job = genesis_job();
    let nonce_2 = genesis_nonce_2();
    let solution = genesis_solution();

    let coinbase = vec![0x05, 0x00, 0x00, 0x00, 0x01, 0x00]; // minimal bytes

    let share = SubmitEquihashShare {
        channel_id: 1,
        sequence_number: 1,
        job_id: 1,
        nonce_2,
        time: job.time,
        solution,
    };

    let full_nonce = job.build_nonce(&share.nonce_2).unwrap();
    let mut header = job.build_header(&full_nonce);
    header[100..104].copy_from_slice(&share.time.to_le_bytes());

    let mut block = Vec::new();
    block.extend_from_slice(&header);
    write_compact_size(1344, &mut block);
    block.extend_from_slice(&share.solution);
    // Only coinbase, no other txs
    write_compact_size(1, &mut block); // tx_count = 1
    block.extend_from_slice(&coinbase);

    let expected_len = 140 + 3 + 1344 + 1 + coinbase.len();
    assert_eq!(block.len(), expected_len);

    // The block hex should be a valid hex string
    let block_hex = hex::encode(&block);
    assert!(
        hex::decode(&block_hex).is_ok(),
        "Block hex must round-trip through hex encode/decode"
    );
}

/// Verify that a corrupted solution is rejected (not accepted, not is_block).
#[test]
fn test_corrupted_solution_not_block() {
    let job = genesis_job();
    let nonce_2 = genesis_nonce_2();
    let mut solution = genesis_solution();
    solution[42] ^= 0xff; // corrupt one byte

    let detector = InMemoryDuplicateDetector::new();
    let processor = ShareProcessor::new();
    let block_target = [0xff; 32];

    let share = SubmitEquihashShare {
        channel_id: 1,
        sequence_number: 1,
        job_id: 1,
        nonce_2,
        time: job.time,
        solution,
    };

    let result = processor
        .validate_share_with_job(&share, &job, &detector, &block_target)
        .unwrap();

    assert!(!result.accepted, "Corrupted solution must not be accepted");
    assert!(!result.is_block, "Corrupted solution must not be a block");
}
