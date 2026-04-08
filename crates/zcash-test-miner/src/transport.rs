use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;
use zcash_mining_protocol::codec::MessageFrame;

use bedrock_noise::{NoiseInitiator, NoiseStream, PublicKey};

pub enum MinerTransport {
    Plain {
        stream: TcpStream,
        read_buf: Vec<u8>,
    },
    Noise(NoiseStream<TcpStream>),
}

impl MinerTransport {
    pub async fn connect(
        addr: &str,
        server_pubkey: Option<&PublicKey>,
    ) -> io::Result<Self> {
        let tcp = TcpStream::connect(addr).await?;
        info!(addr, "TCP connected");

        match server_pubkey {
            Some(pk) => {
                let initiator = NoiseInitiator::new(pk.clone());
                let noise_stream = initiator
                    .connect(tcp)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
                info!("Noise_NK handshake complete");
                Ok(MinerTransport::Noise(noise_stream))
            }
            None => Ok(MinerTransport::Plain {
                stream: tcp,
                read_buf: Vec::with_capacity(4096),
            }),
        }
    }

    pub async fn read_message(&mut self) -> io::Result<Vec<u8>> {
        match self {
            MinerTransport::Noise(noise) => {
                let msg = noise.read_message().await?;
                if msg.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "connection closed",
                    ));
                }
                Ok(msg)
            }
            MinerTransport::Plain { stream, read_buf } => {
                loop {
                    if read_buf.len() >= MessageFrame::HEADER_SIZE {
                        if let Ok(frame) = MessageFrame::decode(read_buf) {
                            let total = MessageFrame::HEADER_SIZE + frame.length as usize;
                            if read_buf.len() >= total {
                                let msg: Vec<u8> = read_buf.drain(..total).collect();
                                return Ok(msg);
                            }
                        }
                    }
                    let mut tmp = [0u8; 4096];
                    let n = stream.read(&mut tmp).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "connection closed",
                        ));
                    }
                    read_buf.extend_from_slice(&tmp[..n]);
                }
            }
        }
    }

    pub async fn write_message(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            MinerTransport::Noise(noise) => {
                noise.write_message(data).await?;
                noise.flush().await?;
            }
            MinerTransport::Plain { stream, .. } => {
                stream.write_all(data).await?;
                stream.flush().await?;
            }
        }
        Ok(())
    }
}
