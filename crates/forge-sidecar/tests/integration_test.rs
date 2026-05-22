//! Integration tests for forge-sidecar

/// Test that the sidecar binary compiles and shows help
#[test]
fn sidecar_help() {
    let output = std::process::Command::new("cargo")
        .args(["run", "-p", "forge-sidecar", "--", "--help"])
        .output()
        .expect("failed to run sidecar");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Forge relay sidecar"),
        "Expected help text to contain 'Forge relay sidecar', got: {}",
        stdout
    );
    assert!(
        stdout.contains("--zebra-url"),
        "Expected help text to contain '--zebra-url'"
    );
    assert!(
        stdout.contains("--relay-peer"),
        "Expected help text to contain '--relay-peer'"
    );
    assert!(
        stdout.contains("--config"),
        "Expected help text to contain '--config'"
    );
    assert!(
        stdout.contains("--receive-relay-blocks"),
        "Expected help text to contain '--receive-relay-blocks'"
    );
    assert!(
        stdout.contains("--disable-template-announcements"),
        "Expected help text to contain '--disable-template-announcements'"
    );
    assert!(
        stdout.contains("--enable-submitblock"),
        "Expected help text to contain '--enable-submitblock'"
    );
}

/// Test configuration parsing
#[test]
fn config_parsing() {
    use std::io::Write;

    let config = r#"
        zebra_url = "http://localhost:8232"
        relay_peers = ["127.0.0.1:8333"]
        poll_interval_ms = 50
    "#;

    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    tmpfile.write_all(config.as_bytes()).unwrap();

    // Just verify it parses - actual runtime would need Zebra
    let _config: toml::Value = toml::from_str(config).unwrap();
}
