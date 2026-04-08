#![no_main]
use forge_sidecar::config::Config;
use libfuzzer_sys::fuzz_target;

// Fuzz TOML config parsing. Exercises toml deserialization and the
// parsed_relay_peers / parsed_auth_key / parsed_bind_addr validation.
fuzz_target!(|data: &[u8]| {
    if let Ok(toml_str) = std::str::from_utf8(data) {
        if let Ok(config) = toml::from_str::<Config>(toml_str) {
            // Exercise all parsing methods - none should panic
            let _ = config.parsed_relay_peers();
            let _ = config.parsed_auth_key();
            let _ = config.parsed_bind_addr();
        }
    }
});
