#![no_main]
use libfuzzer_sys::fuzz_target;
use bedrock_noise::Keypair;

fuzz_target!(|data: &[u8]| {
    // Fuzz Keypair::from_private with arbitrary 32-byte arrays
    if data.len() < 32 {
        return;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&data[..32]);

    // Must never panic
    let kp = Keypair::from_private(arr);

    // Hex roundtrip must not panic
    let hex = kp.private_hex();
    let restored = Keypair::from_private_hex(&hex).expect("roundtrip must succeed");
    assert_eq!(kp.public.as_bytes(), restored.public.as_bytes());

    // Debug/Display must not panic
    let _ = format!("{:?}", kp);
    let _ = format!("{}", kp.public);
    let _ = format!("{:?}", kp.public);
});
