//! The public relay-client-2a29ebd example, frozen from source 2a29ebde863e.
//! No production credentials or operator configuration are included.
use sovright_relay_sidecar::config::Config;

#[test]
fn released_configuration_loads_without_enabling_submission_or_changing_fec() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/relay-client-2a29ebd.toml");
    let config = Config::from_file(&path).unwrap();
    assert_eq!(config.zebra_url, "http://127.0.0.1:8232");
    assert_eq!(config.relay_peers, ["relay.example.com:8333"]);
    assert_eq!((config.data_shards, config.parity_shards), (10, 3));
    assert_eq!(config.poll_interval_ms, 100);
    assert!(config.announce_templates);
    assert!(!config.receive_relay_blocks);
    assert!(!config.enable_submitblock);
    assert!(!config.submit_gate.enabled);
    assert!(config.zebra_url_secondary.is_none());
    assert!(config.auth_key.is_none());
}
