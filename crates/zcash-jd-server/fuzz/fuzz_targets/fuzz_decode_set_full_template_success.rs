#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_jd_server::decode_set_full_template_job_success;

fuzz_target!(|data: &[u8]| {
    let _ = decode_set_full_template_job_success(data);
});
