#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_jd_server::decode_set_custom_job_error;

fuzz_target!(|data: &[u8]| {
    let _ = decode_set_custom_job_error(data);
});
