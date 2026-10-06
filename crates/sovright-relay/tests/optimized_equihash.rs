use sovright_relay::transport::{EquihashPowValidator, PowResult, PowValidator};

#[test]
fn optimized_relay_preserves_mainnet_decisions_and_rejects_corruption() {
    let corpus: serde_json::Value =
        serde_json::from_str(zcash_pool_common::fixtures::EQUIHASH_MAINNET_HEADERS).unwrap();
    for sample in corpus.as_array().unwrap() {
        let full = hex::decode(sample["header"].as_str().unwrap()).unwrap();
        assert_eq!(
            EquihashPowValidator.validate(&full),
            PowResult::Valid,
            "height {}",
            sample["height"]
        );
        for offset in [0, 104, 108, 139, 143, 800, 1486] {
            let mut bad = full.clone();
            bad[offset] ^= 1;
            assert_eq!(EquihashPowValidator.validate(&bad), PowResult::Invalid);
        }
        assert_eq!(
            EquihashPowValidator.validate(&full[..1486]),
            PowResult::Indeterminate
        );
    }
}
