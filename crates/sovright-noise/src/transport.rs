//! Encrypted transport stream wrapper
//!
//! Wraps a TcpStream with Noise encryption, providing AsyncRead/AsyncWrite.

use snow::TransportState;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::trace;

/// Maximum message size for Noise transport (64KB - overhead)
const MAX_MESSAGE_SIZE: usize = 65535 - 16; // 16 bytes for AEAD tag

/// Encrypted stream wrapper.
/// Since all methods take `&mut self`, no interior mutability (Mutex) is needed.
pub struct NoiseStream<S> {
    inner: S,
    transport: TransportState,
}

impl<S> NoiseStream<S> {
    /// Create a new encrypted stream from a completed handshake
    pub fn new(inner: S, transport: TransportState) -> Self {
        Self {
            inner,
            transport,
        }
    }

    /// Get reference to inner stream
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Get mutable reference to inner stream
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consume and return inner stream (drops encryption state)
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl NoiseStream<TcpStream> {
    /// Read an encrypted message and decrypt it
    pub async fn read_message(&mut self) -> io::Result<Vec<u8>> {
        // Read length prefix
        let len = self.inner.read_u16().await? as usize;
        if len == 0 {
            return Ok(Vec::new());
        }

        // Read ciphertext
        let mut ciphertext = vec![0u8; len];
        self.inner.read_exact(&mut ciphertext).await?;

        // Decrypt
        let mut plaintext = vec![0u8; len];
        let plaintext_len = self.transport
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        plaintext.truncate(plaintext_len);
        trace!("Decrypted message: {} bytes", plaintext_len);
        Ok(plaintext)
    }

    /// Encrypt and write a message
    pub async fn write_message(&mut self, plaintext: &[u8]) -> io::Result<()> {
        if plaintext.len() > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Message too large: {} > {}", plaintext.len(), MAX_MESSAGE_SIZE),
            ));
        }

        // Encrypt
        let mut ciphertext = vec![0u8; plaintext.len() + 16]; // AEAD tag
        let ciphertext_len = self.transport
            .write_message(plaintext, &mut ciphertext)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Write with length prefix
        self.inner.write_u16(ciphertext_len as u16).await?;
        self.inner.write_all(&ciphertext[..ciphertext_len]).await?;
        trace!("Encrypted message: {} -> {} bytes", plaintext.len(), ciphertext_len);
        Ok(())
    }

    /// Flush the underlying stream
    pub async fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{NoiseInitiator, NoiseResponder};
    use crate::keys::Keypair;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_encrypted_communication() {
        let server_keypair = Keypair::generate();
        let server_public = server_keypair.public.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server task
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let responder = NoiseResponder::new(server_keypair);
            let mut noise = responder.accept(stream).await.unwrap();

            // Receive message
            let msg = noise.read_message().await.unwrap();
            assert_eq!(msg, b"Hello from client!");

            // Send response
            noise.write_message(b"Hello from server!").await.unwrap();
        });

        // Client
        let client_stream = TcpStream::connect(addr).await.unwrap();
        let initiator = NoiseInitiator::new(server_public);
        let mut client_noise = initiator.connect(client_stream).await.unwrap();

        // Send message
        client_noise.write_message(b"Hello from client!").await.unwrap();

        // Receive response
        let response = client_noise.read_message().await.unwrap();
        assert_eq!(response, b"Hello from server!");

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_large_message() {
        let server_keypair = Keypair::generate();
        let server_public = server_keypair.public.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let responder = NoiseResponder::new(server_keypair);
            let mut noise = responder.accept(stream).await.unwrap();

            let msg = noise.read_message().await.unwrap();
            assert_eq!(msg.len(), 10000);
            assert!(msg.iter().all(|&b| b == 0xAA));
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let initiator = NoiseInitiator::new(server_public);
        let mut client_noise = initiator.connect(client_stream).await.unwrap();

        // Send 10KB message
        let large_msg = vec![0xAA; 10000];
        client_noise.write_message(&large_msg).await.unwrap();

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_empty_message() {
        let server_keypair = Keypair::generate();
        let server_public = server_keypair.public.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let responder = NoiseResponder::new(server_keypair);
            let mut noise = responder.accept(stream).await.unwrap();

            let msg = noise.read_message().await.unwrap();
            assert!(msg.is_empty(), "Expected empty message, got {} bytes", msg.len());
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let initiator = NoiseInitiator::new(server_public);
        let mut client_noise = initiator.connect(client_stream).await.unwrap();

        client_noise.write_message(b"").await.unwrap();

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_max_message_size_boundary() {
        let server_keypair = Keypair::generate();
        let server_public = server_keypair.public.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let max_msg = vec![0xBB; MAX_MESSAGE_SIZE];
        let expected_len = MAX_MESSAGE_SIZE;

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let responder = NoiseResponder::new(server_keypair);
            let mut noise = responder.accept(stream).await.unwrap();

            let msg = noise.read_message().await.unwrap();
            assert_eq!(msg.len(), expected_len);
            assert!(msg.iter().all(|&b| b == 0xBB));
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let initiator = NoiseInitiator::new(server_public);
        let mut client_noise = initiator.connect(client_stream).await.unwrap();

        client_noise.write_message(&max_msg).await.unwrap();

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_over_max_message_size_rejected() {
        let server_keypair = Keypair::generate();
        let server_public = server_keypair.public.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let responder = NoiseResponder::new(server_keypair);
            let _noise = responder.accept(stream).await.unwrap();
            // Server just completes handshake; client will fail before sending
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let initiator = NoiseInitiator::new(server_public);
        let mut client_noise = initiator.connect(client_stream).await.unwrap();

        let oversized_msg = vec![0xCC; MAX_MESSAGE_SIZE + 1];
        let result = client_noise.write_message(&oversized_msg).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_multiple_messages_sequential() {
        let server_keypair = Keypair::generate();
        let server_public = server_keypair.public.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let responder = NoiseResponder::new(server_keypair);
            let mut noise = responder.accept(stream).await.unwrap();

            for i in 0u8..10 {
                let msg = noise.read_message().await.unwrap();
                let expected_len = (i as usize + 1) * 100;
                assert_eq!(msg.len(), expected_len, "Message {} wrong length", i);
                assert!(msg.iter().all(|&b| b == i), "Message {} wrong content", i);
            }
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let initiator = NoiseInitiator::new(server_public);
        let mut client_noise = initiator.connect(client_stream).await.unwrap();

        for i in 0u8..10 {
            let msg = vec![i; (i as usize + 1) * 100];
            client_noise.write_message(&msg).await.unwrap();
        }

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_bidirectional_communication() {
        let server_keypair = Keypair::generate();
        let server_public = server_keypair.public.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let responder = NoiseResponder::new(server_keypair);
            let mut noise = responder.accept(stream).await.unwrap();

            // Echo back each message received
            for _ in 0..5 {
                let msg = noise.read_message().await.unwrap();
                noise.write_message(&msg).await.unwrap();
            }
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let initiator = NoiseInitiator::new(server_public);
        let mut client_noise = initiator.connect(client_stream).await.unwrap();

        for round in 0u8..5 {
            let msg = vec![round; (round as usize + 1) * 200];
            client_noise.write_message(&msg).await.unwrap();

            let echoed = client_noise.read_message().await.unwrap();
            assert_eq!(echoed, msg, "Round {} echo mismatch", round);
        }

        server_handle.await.unwrap();
    }
}
