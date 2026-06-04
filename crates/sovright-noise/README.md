# sovright-noise

> Formerly `zcash-stratum-noise`.

Noise Protocol encryption for Zcash Stratum V2.

## Overview

Implements the Noise NK handshake pattern as used by SV2:
- Server has static keypair (public key shared with clients)
- Client uses ephemeral keys per connection
- ChaCha20-Poly1305 encryption with BLAKE2s

## Usage

### Server Side

```rust
use sovright_noise::{Keypair, NoiseResponder};

let keypair = Keypair::generate();
println!("Public key: {}", keypair.public);

let responder = NoiseResponder::new(&keypair);
let encrypted_stream = responder.accept(tcp_stream).await?;
```

### Client Side

```rust
use sovright_noise::{NoiseInitiator, PublicKey};

let server_key = PublicKey::from_hex("...")?;
let initiator = NoiseInitiator::new(server_key);
let encrypted_stream = initiator.connect(tcp_stream).await?;
```

## Key Management

- Generate: `Keypair::generate()`
- Export: `keypair.private_hex()` / `keypair.public.to_hex()`
- Import: `Keypair::from_private_hex()` / `PublicKey::from_hex()`

## Protocol Details

The implementation uses the `Noise_NK_25519_ChaChaPoly_BLAKE2s` pattern:
- **NK**: Known server key, ephemeral client key
- **25519**: Curve25519 for Diffie-Hellman
- **ChaChaPoly**: ChaCha20-Poly1305 for authenticated encryption
- **BLAKE2s**: BLAKE2s for hashing

## License

MIT OR Apache-2.0
