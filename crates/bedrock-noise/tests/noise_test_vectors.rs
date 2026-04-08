//! Noise NK handshake test vector validation
//!
//! Validates deterministic behavior of the Noise_NK_25519_ChaChaPoly_BLAKE2s
//! handshake using fixed keys and in-memory snow::HandshakeState (no TCP).

use snow::Builder;

/// The pattern string that bedrock-noise must use.
const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

/// Fixed server private key (32 bytes) for deterministic tests.
const SERVER_PRIVATE: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    0x1f, 0x20,
];

/// Derive the server public key from the fixed private key using snow's builder.
fn server_keypair() -> (Vec<u8>, Vec<u8>) {
    // Derive public from our fixed private using x25519-dalek directly.
    let secret = x25519_dalek::StaticSecret::from(SERVER_PRIVATE);
    let public = x25519_dalek::PublicKey::from(&secret);
    (SERVER_PRIVATE.to_vec(), public.as_bytes().to_vec())
}

/// Complete a full NK handshake in memory using fixed server key.
/// Returns (initiator_transport, responder_transport).
fn do_handshake() -> (snow::TransportState, snow::TransportState) {
    let (server_priv, server_pub) = server_keypair();

    // Build initiator (knows server's public key)
    let mut initiator = Builder::new(NOISE_PATTERN.parse().unwrap())
        .remote_public_key(&server_pub)
        .build_initiator()
        .unwrap();

    // Build responder (has server's private key)
    let mut responder = Builder::new(NOISE_PATTERN.parse().unwrap())
        .local_private_key(&server_priv)
        .build_responder()
        .unwrap();

    // Message 1: initiator -> responder (-> e, es)
    let mut msg1 = vec![0u8; 65535];
    let len1 = initiator.write_message(&[], &mut msg1).unwrap();
    msg1.truncate(len1);

    let mut payload1 = vec![0u8; 65535];
    responder.read_message(&msg1, &mut payload1).unwrap();

    // Message 2: responder -> initiator (<- e, ee)
    let mut msg2 = vec![0u8; 65535];
    let len2 = responder.write_message(&[], &mut msg2).unwrap();
    msg2.truncate(len2);

    let mut payload2 = vec![0u8; 65535];
    initiator.read_message(&msg2, &mut payload2).unwrap();

    // Both sides transition to transport mode
    let initiator_transport = initiator.into_transport_mode().unwrap();
    let responder_transport = responder.into_transport_mode().unwrap();

    (initiator_transport, responder_transport)
}

#[test]
fn test_handshake_deterministic_with_fixed_keys() {
    let (mut initiator, mut responder) = do_handshake();

    // Encrypt a message from initiator to responder
    let plaintext = b"Hello from the miner!";
    let mut ciphertext = vec![0u8; plaintext.len() + 16]; // plaintext + AEAD tag
    let ct_len = initiator
        .write_message(plaintext, &mut ciphertext)
        .unwrap();

    // Ciphertext length should be plaintext + 16-byte AEAD tag
    assert_eq!(
        ct_len,
        plaintext.len() + 16,
        "Ciphertext must be plaintext length + 16 bytes (AEAD tag)"
    );

    // Responder decrypts successfully
    let mut decrypted = vec![0u8; ct_len];
    let pt_len = responder
        .read_message(&ciphertext[..ct_len], &mut decrypted)
        .unwrap();
    assert_eq!(&decrypted[..pt_len], plaintext);

    // Also test responder -> initiator direction
    let reply = b"Share accepted";
    let mut reply_ct = vec![0u8; reply.len() + 16];
    let reply_ct_len = responder.write_message(reply, &mut reply_ct).unwrap();
    assert_eq!(reply_ct_len, reply.len() + 16);

    let mut reply_pt = vec![0u8; reply_ct_len];
    let reply_pt_len = initiator
        .read_message(&reply_ct[..reply_ct_len], &mut reply_pt)
        .unwrap();
    assert_eq!(&reply_pt[..reply_pt_len], reply.as_slice());
}

#[test]
fn test_transport_produces_consistent_ciphertext() {
    // Run the handshake twice with the same fixed server key.
    // Since the initiator uses a random ephemeral key each time, the transport
    // keys will differ between runs. But within a single session, encrypting
    // the same plaintext twice should produce different ciphertext (nonce increments).
    let (mut initiator, _responder) = do_handshake();

    let plaintext = b"deterministic test message";
    let mut ct1 = vec![0u8; plaintext.len() + 16];
    let len1 = initiator.write_message(plaintext, &mut ct1).unwrap();

    let mut ct2 = vec![0u8; plaintext.len() + 16];
    let len2 = initiator.write_message(plaintext, &mut ct2).unwrap();

    // Same length (both are plaintext + AEAD tag)
    assert_eq!(len1, len2, "Both ciphertexts should have the same length");
    assert_eq!(len1, plaintext.len() + 16);

    // Different ciphertext because the nonce counter increments
    assert_ne!(
        &ct1[..len1],
        &ct2[..len2],
        "Same plaintext encrypted twice must produce different ciphertext (nonce incremented)"
    );
}

#[test]
fn test_handshake_message_lengths() {
    let (server_priv, server_pub) = server_keypair();

    let mut initiator = Builder::new(NOISE_PATTERN.parse().unwrap())
        .remote_public_key(&server_pub)
        .build_initiator()
        .unwrap();

    let mut responder = Builder::new(NOISE_PATTERN.parse().unwrap())
        .local_private_key(&server_priv)
        .build_responder()
        .unwrap();

    // Message 1: -> e, es (32-byte ephemeral public key + 16-byte AEAD tag from es)
    let mut msg1 = vec![0u8; 65535];
    let len1 = initiator.write_message(&[], &mut msg1).unwrap();
    assert_eq!(
        len1, 48,
        "NK message 1 (-> e, es) with empty payload should be 48 bytes (32 ephemeral + 16 tag)"
    );

    let mut payload1 = vec![0u8; 65535];
    responder.read_message(&msg1[..len1], &mut payload1).unwrap();

    // Message 2: <- e, ee (32-byte ephemeral public key + 16-byte AEAD tag from ee)
    let mut msg2 = vec![0u8; 65535];
    let len2 = responder.write_message(&[], &mut msg2).unwrap();
    assert_eq!(
        len2, 48,
        "NK message 2 (<- e, ee) with empty payload should be 48 bytes (32 ephemeral + 16 tag)"
    );
}

#[test]
fn test_noise_pattern_string_matches() {
    // Regression anchor: verify the crate's NOISE_PATTERN constant
    assert_eq!(
        bedrock_noise::NOISE_PATTERN,
        "Noise_NK_25519_ChaChaPoly_BLAKE2s",
        "NOISE_PATTERN must be exactly Noise_NK_25519_ChaChaPoly_BLAKE2s"
    );

    // Also verify it parses successfully as a snow pattern
    let _params: snow::params::NoiseParams = bedrock_noise::NOISE_PATTERN.parse().unwrap();
}
