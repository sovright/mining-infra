#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_mining_protocol::codec::MessageFrame;

fuzz_target!(|data: &[u8]| {
    let _ = MessageFrame::decode(data);
});
