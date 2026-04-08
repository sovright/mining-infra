//! Test vectors for Equihash (200,9) validation
//!
//! Includes a verified valid solution from the equihash crate's own test vectors.

/// The valid solution bytes from equihash crate v0.2.2 (src/test_vectors/valid.rs)
/// Input: b"block header" (12 bytes), Nonce: [0u8; 32]
fn valid_solution_bytes() -> Vec<u8> {
    hex::decode(
        "0086c8d9f20db2cd9d3e11a3bfa1aa3f3c205afd163d1b6b94a9161d29422c94\
         d28eda00d544e412a7ce1dc96a03e6752951b27cc263f13ccec4d4b393644f292b\
         cd48cfdf7b471821f2aa6a2cd501b88f999dcf0154b4b2612c625bc962c0eb697c\
         2585cf0271b3f2182bc68023e12f77a779637d9faaa5413d55efb58609396718916\
         048378907736e882031e21c23331e1a194b017ceb6f888ba1d30306f23ea1853e82\
         7a20da014dc3eb8bc717b8ede2c37df36f82fa82d5955e880b330fc10a85df38ad5\
         da43e8577dc5a88f6f6f38f0c81bbb7951381e1924f41b533205394cfa4ea630812\
         e372111c0d8968c2db6276d2e985467df119e3d60710e37c65928ad7cba441ce245\
         7df0ccd8d0e64427be15d85112cd1b97cbb592e61eb76a6bec5d8d94e17d2f0c207\
         8aada5270916ffabd31ff9c9da5cc5373c6a56a9072848b1bdfae677c0b69212d50\
         ed73ea700f96d880a1a4a27314011baba141f14a5e8fd86c72d1db5f7f25ca835d1\
         d8f8c11cd050a26f6575cc77149fe580d657608f1e1c3215e8f4187a3b005b40963\
         26aed9702959b3d14dfc775df61eb1e9ccf16acd42853260dfa4f53a140ccd30e096\
         5c271b250ce7113397487b4359f3c03f8be25070f3584ed83e97971c435cf7c31511\
         b62df286b57461575fa22195c14ca486abbe3b8cd66fde158ec095d9e715bc680dbb\
         71b3a0185f0d6bc904df349d9607f1227c6893297944ff80f205b4da4252c31a6f5d\
         347c8430369ce8bb431b7133c2ca00adc3121da6953bad8e79451befe7ffaf528b7f\
         2cb25ca41cb86c25463e578c4620b01567ba6061b08356e4b3a27f5d3b448d1e8ac1\
         d5d70948ecf475b2e43a69e98b712ba9a698fd4638ea56dbf58ff0bdeae65f455995\
         13509b0ec806e845f59271c5bea36476c50518fb1a597a7846a8dac838e38cbd9cee\
         601e7cf50e0054c688f7f50efcdfb989988ff38b7310d876dc6e04c84aa788dc4dd71\
         6bc4cd7e23721a543c654ddc29b04891c84a864b9f6855726df3b9498663c42f75f51\
         ef205ded2e6aa5067212de131cf65090fead36c0d0cceaa82bd577b6c5f0e365fb4ba\
         85ba1825b72b76c911e91c7446bca5665d6af29bdec9fe2a2f4ef295573f72f79765b\
         2a6add705c65458d3ea3df3623e382520056e8ee78fd35427d36d87be296d076a32fa\
         810bb4fa9d8c45e07f3a29321bc4fca8fc3d8f277b71952c932488d6eb37e9d4ca825\
         d7f46b61c2d57e069255f255e2176d824f7bc8de53bda7334256e9d595b90416a9925\
         f374c8bb66bf54ef3c5682202f266b94a105f5c16ef5dd0f407c09b1ac97563927f6d\
         e84db5d563d62c472dcd235a336808afe0f0a3718f4b10391d203775c0390f1cfa7f9\
         8c8a70427941067e51761d1eb541cb28e1cb77d49259c9da46d002252385d4745723f\
         b9e45cf70df0e422963120ec71561adf42e8cc7e2e2842599f3b266df847a1dc54a26\
         b9f14888d5b85f8e12a4d82be168cd4da8b64c8e38006eff2722009badfe2380d073d\
         0a6ad5956901b0398856af65acafd4ec145daa270d87f10c19bc5500bd2de1bcd853c\
         19f8f5377a14ff29768925fefaa30879d77f8e988d4746ee9305f7cc6bad2e431fbd5\
         a0a4562829a0f7f78bca9512d63607a39591fefa33f082482587287d2ace9a55b5b3b\
         e29e66e403dcd0f11dfb55162e09398ebdaff201e35cfc7d30a7beb90c086b88772c5\
         4c62dc3843340a24ee860e0ac189f591c98fbb51ee84e357cb11a038e70256f3958df\
         2107124cf1731b17f545990382099fc2e3d6315f541e162c22ad4050f072bfa2b7495\
         7c8e08e7295569c3c80128c5adac4bca463f9894216c13be9cd4d98d6a9005d908fcf\
         b71c6517f23968ab31f6c1a748d79e1712",
    )
    .expect("valid hex for solution")
}

#[test]
fn test_equihash_raw_valid_solution() {
    // Verify the test vector works directly with the equihash crate API.
    // Input: b"block header" (12 bytes), Nonce: [0u8; 32], params: (200, 9)
    let input = b"block header";
    let nonce = [0u8; 32];
    let solution = valid_solution_bytes();

    assert_eq!(solution.len(), 1344, "Solution must be exactly 1344 bytes");

    equihash::is_valid_solution(200, 9, input, &nonce, &solution)
        .expect("Test vector solution should be valid for (200,9)");
}

#[test]
fn test_equihash_validator_verify_solution() {
    // The EquihashValidator::verify_solution method requires a 140-byte header where
    // bytes [0..108] are the input and bytes [108..140] are the nonce. The test vector
    // uses a 12-byte input (b"block header"), so zero-padding to 108 bytes changes
    // the Blake2b hash and invalidates the solution.
    //
    // Therefore, we verify the raw API works, then separately confirm that the
    // validator's verify_share path functions correctly by using a permissive target.
    // Since the zero-padded header won't produce a valid equihash solution, we expect
    // the validator to correctly reject it at the equihash verification step.

    use zcash_equihash_validator::EquihashValidator;

    let solution = valid_solution_bytes();
    let validator = EquihashValidator::new();

    // Build a 140-byte header: 12-byte input zero-padded to 108 + 32-byte nonce
    let mut header = [0u8; 140];
    header[..12].copy_from_slice(b"block header");
    // nonce is already zeros

    // This SHOULD fail because the zero-padded 108-byte input is not the same
    // as the original 12-byte input for equihash purposes.
    let result = validator.verify_solution(&header, &solution);
    assert!(
        result.is_err(),
        "Zero-padded 108-byte input should NOT produce valid solution \
         (equihash is sensitive to exact input length)"
    );
}

#[test]
fn test_equihash_invalid_solution_rejected() {
    // Use the valid test vector but corrupt one byte of the solution.
    let input = b"block header";
    let nonce = [0u8; 32];
    let mut solution = valid_solution_bytes();

    // Corrupt the first non-zero byte
    solution[1] ^= 0xff;

    let result = equihash::is_valid_solution(200, 9, input, &nonce, &solution);
    assert!(
        result.is_err(),
        "Corrupted solution must be rejected by equihash validation"
    );
}

#[test]
fn test_validator_rejects_wrong_solution_size() {
    use zcash_equihash_validator::EquihashValidator;

    let validator = EquihashValidator::new();
    let header = [0u8; 140];

    // Too short
    let short_solution = vec![0u8; 1343];
    let result = validator.verify_solution(&header, &short_solution);
    assert!(result.is_err(), "Solution shorter than 1344 bytes must be rejected");

    // Too long
    let long_solution = vec![0u8; 1345];
    let result = validator.verify_solution(&header, &long_solution);
    assert!(result.is_err(), "Solution longer than 1344 bytes must be rejected");

    // Empty
    let empty_solution: Vec<u8> = vec![];
    let result = validator.verify_solution(&header, &empty_solution);
    assert!(result.is_err(), "Empty solution must be rejected");
}

#[test]
fn test_validator_rejects_wrong_header_size() {
    use zcash_equihash_validator::EquihashValidator;

    let validator = EquihashValidator::new();
    let solution = vec![0u8; 1344];

    // Too short
    let short_header = vec![0u8; 139];
    let result = validator.verify_solution(&short_header, &solution);
    assert!(result.is_err(), "Header shorter than 140 bytes must be rejected");

    // Too long
    let long_header = vec![0u8; 141];
    let result = validator.verify_solution(&long_header, &solution);
    assert!(result.is_err(), "Header longer than 140 bytes must be rejected");

    // Empty
    let empty_header: Vec<u8> = vec![];
    let result = validator.verify_solution(&empty_header, &solution);
    assert!(result.is_err(), "Empty header must be rejected");

    // Bitcoin-sized header (80 bytes)
    let btc_header = vec![0u8; 80];
    let result = validator.verify_solution(&btc_header, &solution);
    assert!(result.is_err(), "80-byte Bitcoin header must be rejected");
}

// ---------------------------------------------------------------------------
// Zcash mainnet genesis block test vectors (from Zebra's test suite)
// ---------------------------------------------------------------------------

/// Returns the 140-byte genesis block header
fn genesis_block_header() -> Vec<u8> {
    hex::decode(
        "04000000\
         0000000000000000000000000000000000000000000000000000000000000000\
         db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac4\
         0000000000000000000000000000000000000000000000000000000000000000\
         90041358\
         ffff071f\
         5712000000000000000000000000000000000000000000000000000000000000",
    )
    .expect("valid hex for genesis header")
}

/// Returns the 1344-byte genesis block solution
fn genesis_block_solution() -> Vec<u8> {
    hex::decode(
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
    .expect("valid hex for genesis solution")
}

#[test]
fn test_zcash_genesis_block_valid_solution() {
    use zcash_equihash_validator::EquihashValidator;

    let header = genesis_block_header();
    let solution = genesis_block_solution();

    assert_eq!(header.len(), 140, "Genesis header must be 140 bytes");
    assert_eq!(solution.len(), 1344, "Genesis solution must be 1344 bytes");

    let validator = EquihashValidator::new();
    validator
        .verify_solution(&header, &solution)
        .expect("Genesis block solution must be valid");
}

#[test]
fn test_zcash_genesis_block_corrupted_solution_rejected() {
    use zcash_equihash_validator::EquihashValidator;

    let header = genesis_block_header();
    let mut solution = genesis_block_solution();

    // Flip one byte in the solution to corrupt it
    solution[42] ^= 0xff;

    let validator = EquihashValidator::new();
    let result = validator.verify_solution(&header, &solution);
    assert!(
        result.is_err(),
        "Corrupted genesis solution must be rejected"
    );
}

#[test]
fn test_zcash_genesis_block_verify_share_with_easy_target() {
    use zcash_equihash_validator::EquihashValidator;

    let header = genesis_block_header();
    let solution = genesis_block_solution();

    let validator = EquihashValidator::new();
    // Very easy target (all 0xff) -- any valid solution should meet it
    let easy_target = [0xff; 32];
    let hash = validator
        .verify_share(&header, &solution, &easy_target)
        .expect("Valid genesis solution with easy target must return Ok(hash)");

    // The hash should be non-zero (a real block hash)
    assert_ne!(hash, [0u8; 32], "Block hash should be non-zero");
}

#[test]
fn test_zcash_genesis_block_verify_share_with_impossible_target() {
    use zcash_equihash_validator::{EquihashValidator, ValidationError};

    let header = genesis_block_header();
    let solution = genesis_block_solution();

    let validator = EquihashValidator::new();
    // Impossible target (all zeros) -- no hash can be <= 0
    let impossible_target = [0x00; 32];
    let result = validator.verify_share(&header, &solution, &impossible_target);

    match result {
        Err(ValidationError::TargetNotMet) => {} // Expected
        Err(e) => panic!("Expected TargetNotMet, got: {e}"),
        Ok(_) => panic!("Expected TargetNotMet error, but got Ok"),
    }
}
