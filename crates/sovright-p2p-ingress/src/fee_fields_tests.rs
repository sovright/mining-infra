//! ZIP-317 fee fields on `tx_seen` payload events, checked against real mainnet
//! transactions.
//!
//! Vectors are raw `getrawtransaction` hex of mined transactions from our Zebra
//! node. Expected logical actions agree with the Python reference
//! (`tools/inclusion_forecast/fees.py::logical_actions` in the deployment repo)
//! and the `logical_actions` the inclusion pipeline recorded for each block.
//! Expected fees are that pipeline's `fee_zat` (Zebra's own valueZat/value
//! balances). Prevout values come from Zebra RPC for each spent outpoint.

use crate::observation::tx_payload_event;
use crate::wtxid::parse_tx_bytes;
use serde_json::Value;
use std::collections::HashMap;

const FEE_KEYS: [&str; 7] = [
    "zip317_logical_actions",
    "value_balance_zat",
    "sprout_vpub_new_minus_old_zat",
    "transparent_out_zat",
    "transparent_inputs",
    "transparent_input_count",
    "fee_fields_version",
];

fn vector(txid: &str) -> Vec<u8> {
    let hex = match txid {
        "604001faab2706d72791f2ea019017fa68e5e392595056872411ba59913aef32" => include_str!(
            "../tests/fixtures/fee_vectors/604001faab2706d72791f2ea019017fa68e5e392595056872411ba59913aef32.hex"
        ),
        "c6cc7eded2beca3a9a246fd2f420eab336470fab4edb007ec2c1ef344381f31a" => include_str!(
            "../tests/fixtures/fee_vectors/c6cc7eded2beca3a9a246fd2f420eab336470fab4edb007ec2c1ef344381f31a.hex"
        ),
        "149c042a93c63848664a4ef65892a754a4a207927fa51855dbab05fe55f701a7" => include_str!(
            "../tests/fixtures/fee_vectors/149c042a93c63848664a4ef65892a754a4a207927fa51855dbab05fe55f701a7.hex"
        ),
        "34a4ecace712e09a2b9edcbb855f7e09c7e11eebf83989016d37023745b5e028" => include_str!(
            "../tests/fixtures/fee_vectors/34a4ecace712e09a2b9edcbb855f7e09c7e11eebf83989016d37023745b5e028.hex"
        ),
        "5c811e626a7a1d0c5c57279745d7764c5ec201afb054d3e87ddabc230fb701da" => include_str!(
            "../tests/fixtures/fee_vectors/5c811e626a7a1d0c5c57279745d7764c5ec201afb054d3e87ddabc230fb701da.hex"
        ),
        "ab809bb8d540363bf2be5c0d824e243d396ab8b853f735fc5e0941993c8f8237" => include_str!(
            "../tests/fixtures/fee_vectors/ab809bb8d540363bf2be5c0d824e243d396ab8b853f735fc5e0941993c8f8237.hex"
        ),
        "1877e06a8e1bfa63873f2d3da5a3dfea06428b33207c00635e3c3433ce7e4053" => include_str!(
            "../tests/fixtures/fee_vectors/1877e06a8e1bfa63873f2d3da5a3dfea06428b33207c00635e3c3433ce7e4053.hex"
        ),
        "367e867a87e978b66fae9912cf7693c0c5e16da11aa268bf32f8dcad69061c5d" => include_str!(
            "../tests/fixtures/fee_vectors/367e867a87e978b66fae9912cf7693c0c5e16da11aa268bf32f8dcad69061c5d.hex"
        ),
        other => panic!("no vector {other}"),
    };
    hex::decode(hex.trim()).unwrap()
}

/// The emitted `tx_seen` payload event for a vector.
fn event(txid: &str) -> Value {
    let bytes = vector(txid);
    let (_, metadata) = parse_tx_bytes(&bytes).expect("vector parses");
    assert_eq!(metadata.txid, txid, "fixture identity");
    tx_payload_event(&metadata, bytes.len())
}

/// What a consumer does: transparent inputs (from its own prevout lookup) minus
/// transparent outputs, plus every shielded value balance.
fn fee_from_event(event: &Value, prevouts: &[(&str, i64)]) -> i64 {
    let values: HashMap<&str, i64> = prevouts.iter().copied().collect();
    let inputs = event["transparent_inputs"].as_array().unwrap();
    assert_eq!(
        event["transparent_input_count"].as_u64().unwrap() as usize,
        prevouts.len(),
        "fee test needs every prevout"
    );
    assert_eq!(inputs.len(), prevouts.len());
    let t_in: i64 = inputs.iter().map(|i| values[i.as_str().unwrap()]).sum();
    let vb = &event["value_balance_zat"];
    t_in - event["transparent_out_zat"].as_i64().unwrap()
        + vb["sapling"].as_i64().unwrap()
        + vb["orchard"].as_i64().unwrap()
        + vb["ironwood"].as_i64().unwrap()
        + event["sprout_vpub_new_minus_old_zat"].as_i64().unwrap()
}

struct Case {
    txid: &'static str,
    logical_actions: u64,
    sapling: i64,
    orchard: i64,
    ironwood: i64,
    transparent_out: u64,
    prevouts: &'static [(&'static str, i64)],
    fee_zat: i64,
}

const CASES: &[Case] = &[
    // Pure Ironwood flood tx: 2 actions, 800 zat, 9,166 bytes.
    Case {
        txid: "604001faab2706d72791f2ea019017fa68e5e392595056872411ba59913aef32",
        logical_actions: 2,
        sapling: 0,
        orchard: 0,
        ironwood: 800,
        transparent_out: 0,
        prevouts: &[],
        fee_zat: 800,
    },
    // Orchard v5: 2 actions plus one transparent output (unshield).
    Case {
        txid: "c6cc7eded2beca3a9a246fd2f420eab336470fab4edb007ec2c1ef344381f31a",
        logical_actions: 3,
        sapling: 0,
        orchard: 75000,
        ironwood: 0,
        transparent_out: 72000,
        prevouts: &[],
        fee_zat: 3000,
    },
    // Transparent v5, 1 in / 3 out: output bytes, not the output count, give 5.
    Case {
        txid: "149c042a93c63848664a4ef65892a754a4a207927fa51855dbab05fe55f701a7",
        logical_actions: 5,
        sapling: 0,
        orchard: 0,
        ironwood: 0,
        transparent_out: 95439036,
        prevouts: &[(
            "aaac47f62061aff264c524af3ba1d66b44998afbb93992e57f92369e9f278e88:0",
            95464036,
        )],
        fee_zat: 25000,
    },
    // Transparent v6, 3 in / 2 out.
    Case {
        txid: "34a4ecace712e09a2b9edcbb855f7e09c7e11eebf83989016d37023745b5e028",
        logical_actions: 3,
        sapling: 0,
        orchard: 0,
        ironwood: 0,
        transparent_out: 268444227,
        prevouts: &[
            (
                "68917ff4401f5f55181412f1585b07af0834263669bdef0fa01592de242f2a84:0",
                78951808,
            ),
            (
                "6e5c8159ea40b2a40fb52ea254c877b0d8df0b17f0ab12162804b2ea7b0626cd:0",
                89507419,
            ),
            (
                "f81f9221e6ca3c7e6dfbb13e4dfb7c094da32f998490409f64560be3b66f8a66:0",
                100000000,
            ),
        ],
        fee_zat: 15000,
    },
    // Transparent v5, 6 non-P2PKH-sized inputs / 2 out: input bytes give 11.
    Case {
        txid: "5c811e626a7a1d0c5c57279745d7764c5ec201afb054d3e87ddabc230fb701da",
        logical_actions: 11,
        sapling: 0,
        orchard: 0,
        ironwood: 0,
        transparent_out: 1035590900,
        prevouts: &[
            (
                "d46d3f05bf20e872c7a638e77811af260d9ac6ba09f947befc981d01ce561179:0",
                92000000,
            ),
            (
                "bedaa950c229784de63d4200616c6541cdecf5d53a17d56f84a380254c48888d:0",
                2000000,
            ),
            (
                "0acbaa701ce53f8898a90b6541cf47d1de435ca147a7416f5ef03d44142715f7:0",
                114000000,
            ),
            (
                "e62c9bca63b93862f3f7b93cffa1fb97832aa8aea9dca63b1f9dbeb7d2977923:1",
                247655900,
            ),
            (
                "dea8cce506af122be6df8a8c9d4624418db9c6feaacae40a1c4e7c8fedb20a18:0",
                285000000,
            ),
            (
                "33b4413304636459438cf2bff051cd5bd93e32956f14c2733fd8e0b3ff68e09c:1",
                294990000,
            ),
        ],
        fee_zat: 55000,
    },
    // Sapling v5: 1 spend / 2 outputs, unshielding to one transparent output.
    Case {
        txid: "ab809bb8d540363bf2be5c0d824e243d396ab8b853f735fc5e0941993c8f8237",
        logical_actions: 3,
        sapling: 110385000,
        orchard: 0,
        ironwood: 0,
        transparent_out: 110370000,
        prevouts: &[],
        fee_zat: 15000,
    },
    // Sapling v5 shielding 23 transparent inputs: negative Sapling balance.
    Case {
        txid: "1877e06a8e1bfa63873f2d3da5a3dfea06428b33207c00635e3c3433ce7e4053",
        logical_actions: 25,
        sapling: -958563064,
        orchard: 0,
        ironwood: 0,
        transparent_out: 0,
        prevouts: &[
            (
                "ecb61ec781cbd9d3ccd6a1c990b80f00e83586a58da69405858ee50cf7150c01:0",
                41666668,
            ),
            (
                "4c097448f4f5e4fe0bb7f0bbdbff08e9900426b8ff9d6e4bbf3cbdcf225d620c:0",
                41823468,
            ),
            (
                "5eda0bd56c54c51aa354a9540f1925b2724f85c119f5b3c43b7de163c9d2df0e:0",
                41666668,
            ),
            (
                "cd1f297935d703bfce17032210518eb4d0899dc0b662c875c5202cda52a6352f:0",
                41743188,
            ),
            (
                "01e8fe461b643b069998046dec3308c4a61cc86667208f07ff03862486b0873c:0",
                41666668,
            ),
            (
                "b473e4785c06e32f4622cd811a14fccbf56f8e5082b229650ad52a699f15c946:0",
                41666668,
            ),
            (
                "d4e755f0231e9a04e1de47c86e214aec1e001bd088c3f6ba2245a450ee446548:0",
                41666668,
            ),
            (
                "022e28ecf63cec7ed75729031c66b85bc519ab5313dd8c678d821ae63c456857:0",
                41671468,
            ),
            (
                "e4728be9ee51685465f665a6c3a36eac05305081cbdaa2edfc171cb2bbb9df5c:0",
                41666668,
            ),
            (
                "41c0c97b80f3c51c3e44dbef56e8ce6caa620cd57f0f74c5a66cee62720fd982:0",
                41666668,
            ),
            (
                "2ce8810b81684673424459421447856a06db017cf11024e2d3e47f4f9646d585:0",
                41666668,
            ),
            (
                "6693c353ee7f7e2dde38188e285705f2b0369b1447ec0041e8cedb7c318d7488:0",
                41666668,
            ),
            (
                "6851490a57bbef0a7571a37782eb41a9ad4f0908f9ce5c9b30303ad48d169b90:0",
                41666668,
            ),
            (
                "9eda3f19e085e0de542e2fec70f19f8ad766f736fe9ea9041c5e54976289e593:0",
                41666668,
            ),
            (
                "b262960da59b1463b59d4b51b044f33573522e4fcb1e0498fd197d925013569f:0",
                41666668,
            ),
            (
                "90b0c7d4b49576b5d776d61a4a0f77a0d4c6907c335d3b7f067e0c1813221fa1:0",
                41747248,
            ),
            (
                "297ccf528c3632a9cf5b0b1b1df84ffdbbdc916cf16208327610a303d6067aaa:0",
                41666668,
            ),
            (
                "6a86cb804f814a580bc9862a5dfefe171acd30bba4bc44c1f185a183d3ec12c8:0",
                41666668,
            ),
            (
                "4067f027d44f4df13837a9286390fddb967bf5444586f72df3130066b276fbc8:0",
                41666668,
            ),
            (
                "5c1239fcbf97e5384df0ff20e6426d76c84b0a72a9122e31a486c224d75004cc:0",
                41702668,
            ),
            (
                "b727c9fca53a2a5bff9d688bbde481683118880f9ac05bde3b8c89d208f1a7cd:0",
                41666668,
            ),
            (
                "eb415b33c2aac8e7826fe5586cf98097f440bb5ced412d819d289dfa452d28d6:0",
                41666668,
            ),
            (
                "9f1ec71014682a4e49faf8bdec3e0d9fc0265fc2d35966e9e7831279cff53adb:0",
                41666668,
            ),
        ],
        fee_zat: 125000,
    },
];

#[test]
fn fee_fields_reproduce_known_mainnet_fees() {
    for case in CASES {
        let e = event(case.txid);
        let t = case.txid;
        assert_eq!(e["fee_fields_version"], 1, "{t}");
        assert_eq!(e["zip317_logical_actions"], case.logical_actions, "{t}");
        assert_eq!(e["value_balance_zat"]["sapling"], case.sapling, "{t}");
        assert_eq!(e["value_balance_zat"]["orchard"], case.orchard, "{t}");
        assert_eq!(e["value_balance_zat"]["ironwood"], case.ironwood, "{t}");
        assert_eq!(e["sprout_vpub_new_minus_old_zat"], 0, "{t}");
        assert_eq!(e["transparent_out_zat"], case.transparent_out, "{t}");
        // Outpoint order and display byte order match Zebra's vin[].txid/vout.
        let inputs: Vec<&str> = e["transparent_inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let want: Vec<&str> = case.prevouts.iter().map(|(o, _)| *o).collect();
        assert_eq!(inputs, want, "{t}");
        assert_eq!(fee_from_event(&e, case.prevouts), case.fee_zat, "{t}");
        // Existing fields are unchanged.
        assert_eq!(e["event"], "tx_seen");
        assert_eq!(e["stage"], "payload");
        assert_eq!(e["txid"], t);
    }
}

#[test]
fn ironwood_flood_vector_is_the_documented_shape() {
    let bytes = vector("604001faab2706d72791f2ea019017fa68e5e392595056872411ba59913aef32");
    assert_eq!(bytes.len(), 9166);
    let e = event("604001faab2706d72791f2ea019017fa68e5e392595056872411ba59913aef32");
    assert_eq!(e["tx_version"], 6);
    assert_eq!(e["size_bytes"], 9166);
    assert_eq!(e["transparent_input_count"], 0);
    assert_eq!(e["transparent_inputs"], serde_json::json!([]));
}

/// 71 P2PKH inputs: the size rule gives 70 logical actions where a plain input
/// count would give 71. The outpoint list is capped at 64, the count is not.
#[test]
fn transparent_inputs_are_capped_but_counted_and_size_rule_applies() {
    let e = event("367e867a87e978b66fae9912cf7693c0c5e16da11aa268bf32f8dcad69061c5d");
    assert_eq!(e["zip317_logical_actions"], 70);
    assert_eq!(e["transparent_input_count"], 71);
    assert_eq!(e["transparent_out_zat"], 587025011u64);
    let inputs = e["transparent_inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 64);
    assert_eq!(
        inputs[0],
        "427cebeb0dc4989be7dc879d4bfc1a9b7b60d2948d78a7257e8e50c93f7693f3:13"
    );
    assert_eq!(
        inputs[63],
        "418315fa63fc1f536d89acf592ffaf2a857a8b470317803504d6c070b230a6ba:0"
    );
}

#[test]
fn missing_fee_fields_emit_none_of_the_keys() {
    let bytes = vector("604001faab2706d72791f2ea019017fa68e5e392595056872411ba59913aef32");
    let (_, mut metadata) = parse_tx_bytes(&bytes).unwrap();
    metadata.fee_fields = None;
    let e = tx_payload_event(&metadata, bytes.len());
    for key in FEE_KEYS {
        assert!(e.get(key).is_none(), "{key} must be absent");
    }
    assert_eq!(e["txid"], metadata.txid);
    assert_eq!(e["action_count"], metadata.action_count);
}

#[test]
fn every_vector_emits_all_fee_keys() {
    for case in CASES {
        let e = event(case.txid);
        for key in FEE_KEYS {
            assert!(e.get(key).is_some(), "{} missing {key}", case.txid);
        }
    }
}
