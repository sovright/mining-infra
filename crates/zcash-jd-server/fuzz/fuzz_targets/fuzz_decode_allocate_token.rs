#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_jd_server::decode_allocate_token;

fuzz_target!(|data: &[u8]| {
    let _ = decode_allocate_token(data);
});
