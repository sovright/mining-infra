//! Integration tests for relay
//!
//! These tests require the "relay" feature to be enabled.

#[cfg(feature = "relay")]
mod relay_tests {
    use zcash_pool_server::config::PoolConfig;
    use zcash_pool_server::RelayHandle;

    /// Test that RelayHandle can be created with valid config
    #[test]
    fn test_relay_creation() {
        let mut config = PoolConfig::default();
        config.relay_enabled = true;
        config.relay_peers = vec!["127.0.0.1:8336".parse().unwrap()];
        config.relay_auth_key = Some([0x42; 32]);

        let relay = RelayHandle::new(&config);
        assert!(relay.is_ok(), "RelayHandle should create successfully");
    }

    /// Test that RelayHandle fails with empty peers
    #[test]
    fn test_relay_requires_peers() {
        let mut config = PoolConfig::default();
        config.relay_enabled = true;
        config.relay_peers = vec![]; // Empty!

        let relay = RelayHandle::new(&config);
        assert!(relay.is_err(), "RelayHandle should fail with empty peers");
    }
}

/// Test that disabled relay doesn't interfere with pool startup
#[test]
fn test_pool_server_without_relay() {
    let config = zcash_pool_server::config::PoolConfig::default();
    // relay_enabled defaults to false

    let server = zcash_pool_server::PoolServer::new(config);
    assert!(server.is_ok(), "Pool server should start without relay");
}
