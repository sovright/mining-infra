#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_jd_server::decode_push_solution;

fuzz_target!(|data: &[u8]| {
    let _ = decode_push_solution(data);
});
