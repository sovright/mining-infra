#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_template_provider::parse_target;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary byte sequences as potential target hex strings
    if let Ok(s) = std::str::from_utf8(data) {
        // Must never panic, only return Ok or Err
        let _ = parse_target(s);
    }
});
