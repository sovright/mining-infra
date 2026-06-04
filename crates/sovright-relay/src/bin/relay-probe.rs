use std::env;
use std::net::SocketAddr;

use sovright_relay::{
    BlockChunker, Chunk, ChunkHeader, CompactBlock, PrefilledTx, RelaySession, ShortId,
};
use tokio::net::UdpSocket;

const DEFAULT_BIND_ADDR: &str = "0.0.0.0:0";
const DEFAULT_HEADER_LEN: usize = 2_189;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let relay_addrs = relay_addrs_from_env()?;
    let auth_key = parse_auth_key(
        &env::var("SOVRIGHT_RELAY_PROBE_AUTH_KEY_HEX")
            .or_else(|_| env::var("SOVRIGHT_RELAY_AUTH_KEY_HEX"))?,
    )?;
    let bind_addr: SocketAddr = env::var("SOVRIGHT_RELAY_PROBE_BIND_ADDR")
        .unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string())
        .parse()?;
    let data_shards = env_usize("SOVRIGHT_RELAY_DATA_SHARDS", 10)?;
    let parity_shards = env_usize("SOVRIGHT_RELAY_PARITY_SHARDS", 3)?;

    let compact = synthetic_compact_block();
    let block_hash = *compact.header_hash().as_bytes();
    let chunker = BlockChunker::new(data_shards, parity_shards)?;
    let chunks = chunker.compact_block_to_chunks(&compact, &block_hash)?;
    let socket = UdpSocket::bind(bind_addr).await?;
    let session = RelaySession::new(socket.local_addr()?, auth_key);

    let mut packets_sent = 0usize;
    for relay_addr in &relay_addrs {
        for chunk in &chunks {
            let hmac = session.compute_hmac(
                &chunk.header.block_hash,
                chunk.header.chunk_id,
                chunk.header.total_chunks,
                chunk.header.payload_len,
                &chunk.payload,
            );
            let header = ChunkHeader::new_block_authenticated(
                &block_hash,
                chunk.header.chunk_id,
                chunk.header.total_chunks,
                chunk.header.payload_len,
                hmac,
            );
            let auth_chunk = Chunk::new(header, chunk.payload.clone());
            socket.send_to(&auth_chunk.to_bytes(), relay_addr).await?;
            packets_sent += 1;
        }
    }

    println!(
        "{{\"event\":\"sovright_relay_probe_sent\",\"authenticated\":true,\"relays\":{},\"chunks_per_relay\":{},\"packets_sent\":{},\"block_hash\":\"{}\"}}",
        relay_addrs.len(),
        chunks.len(),
        packets_sent,
        hex::encode(block_hash),
    );

    Ok(())
}

fn relay_addrs_from_env() -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    let value = env::var("SOVRIGHT_RELAY_PROBE_RELAY_ADDRS")
        .or_else(|_| env::var("SOVRIGHT_RELAY_RELAY_ADDRS"))?;
    let addrs: Result<Vec<_>, _> = value
        .split(',')
        .map(str::trim)
        .filter(|addr| !addr.is_empty())
        .map(str::parse)
        .collect();
    let addrs = addrs?;
    if addrs.is_empty() {
        return Err("at least one relay address is required".into());
    }
    Ok(addrs)
}

fn parse_auth_key(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let bytes = hex::decode(value.trim())?;
    if bytes.len() != 32 {
        return Err(format!("auth key must be 32 bytes, got {}", bytes.len()).into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn env_usize(
    name: &str,
    default: usize,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(_) => Ok(default),
    }
}

fn synthetic_compact_block() -> CompactBlock {
    let mut header = vec![0u8; DEFAULT_HEADER_LEN];
    header[0..4].copy_from_slice(&4u32.to_le_bytes());
    header[4..36].copy_from_slice(&[0x42; 32]);
    header[36..68].copy_from_slice(&[0x24; 32]);
    header[68..100].copy_from_slice(&[0x99; 32]);
    header[100..132].copy_from_slice(&[0x51; 32]);
    header[132..164].copy_from_slice(&[0x73; 32]);
    header[164..196].copy_from_slice(&[0x20; 32]);
    header[196..228].copy_from_slice(&[0x26; 32]);
    header[228..260].copy_from_slice(&[0x05; 32]);

    CompactBlock::new(
        header,
        0xbed0_2026_0521,
        Vec::<ShortId>::new(),
        vec![PrefilledTx {
            index: 0,
            tx_data: b"sovright-relay-probe".to_vec(),
        }],
    )
}
