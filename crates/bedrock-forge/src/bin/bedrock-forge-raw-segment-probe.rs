use std::env;
use std::fs;
use std::net::SocketAddr;
use std::time::Duration;

use bedrock_forge::{
    BlockChunker, Chunk, ChunkHeader, RelaySession, ZCASH_FULL_HEADER_SIZE, split_raw_block,
};
use tokio::net::UdpSocket;
use tokio::time::sleep;

const DEFAULT_BIND_ADDR: &str = "0.0.0.0:0";
const DEFAULT_SEGMENT_FRAME_BYTES: usize = 64 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let relay_addrs = relay_addrs_from_env()?;
    let auth_key = parse_auth_key(
        &env::var("BEDROCK_FORGE_PROBE_AUTH_KEY_HEX")
            .or_else(|_| env::var("BEDROCK_FORGE_AUTH_KEY_HEX"))?,
    )?;
    let bind_addr: SocketAddr = env::var("BEDROCK_FORGE_PROBE_BIND_ADDR")
        .unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string())
        .parse()?;
    let data_shards = env_usize("BEDROCK_FORGE_DATA_SHARDS", 10)?;
    let parity_shards = env_usize("BEDROCK_FORGE_PARITY_SHARDS", 3)?;
    let segment_frame_bytes = env_usize(
        "BEDROCK_FORGE_RAW_SEGMENT_FRAME_BYTES",
        DEFAULT_SEGMENT_FRAME_BYTES,
    )?;
    let packet_delay =
        Duration::from_micros(env_u64("BEDROCK_FORGE_PROBE_PACKET_DELAY_MICROS", 0)?);
    let segment_delay = Duration::from_millis(env_u64("BEDROCK_FORGE_PROBE_SEGMENT_DELAY_MS", 0)?);

    let raw_block = raw_block_from_env()?;
    if raw_block.len() < ZCASH_FULL_HEADER_SIZE {
        return Err(format!(
            "raw block too short for Zcash header: {} bytes",
            raw_block.len()
        )
        .into());
    }
    let block_hash = raw_block_header_hash(&raw_block[..ZCASH_FULL_HEADER_SIZE]);
    let segments = split_raw_block(block_hash, &raw_block, segment_frame_bytes)?;
    let chunker = BlockChunker::new(data_shards, parity_shards)?;
    let socket = UdpSocket::bind(bind_addr).await?;
    let session = RelaySession::new(socket.local_addr()?, auth_key);

    let mut packets_sent = 0usize;
    for relay_addr in &relay_addrs {
        for segment in &segments {
            let chunks = chunker.raw_block_segment_to_chunks(segment)?;
            for chunk in chunks {
                let auth_chunk = authenticate_raw_segment_chunk(&session, &chunk);
                socket.send_to(&auth_chunk.to_bytes(), relay_addr).await?;
                packets_sent += 1;
                if !packet_delay.is_zero() {
                    sleep(packet_delay).await;
                }
            }
            if !segment_delay.is_zero() {
                sleep(segment_delay).await;
            }
        }
    }

    println!(
        "{{\"event\":\"bedrock_forge_raw_segment_probe_sent\",\"authenticated\":true,\"relays\":{},\"segments\":{},\"packets_sent\":{},\"block_hash\":\"{}\",\"raw_block_bytes\":{},\"segment_frame_bytes\":{}}}",
        relay_addrs.len(),
        segments.len(),
        packets_sent,
        hex::encode(block_hash),
        raw_block.len(),
        segment_frame_bytes,
    );

    Ok(())
}

fn relay_addrs_from_env() -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    let value = env::var("BEDROCK_FORGE_PROBE_RELAY_ADDRS")
        .or_else(|_| env::var("BEDROCK_FORGE_RELAY_ADDRS"))?;
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

fn env_u64(name: &str, default: u64) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(_) => Ok(default),
    }
}

fn raw_block_from_env() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(path) = env::var("BEDROCK_FORGE_RAW_BLOCK_HEX_FILE") {
        return decode_hex_block(&fs::read_to_string(path)?);
    }
    let value = env::var("BEDROCK_FORGE_RAW_BLOCK_HEX")?;
    decode_hex_block(&value)
}

fn decode_hex_block(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let trimmed: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    Ok(hex::decode(trimmed)?)
}

fn authenticate_raw_segment_chunk(session: &RelaySession, chunk: &bedrock_forge::Chunk) -> Chunk {
    let hmac = session.compute_hmac(
        &chunk.header.block_hash,
        chunk.header.chunk_id,
        chunk.header.total_chunks,
        chunk.header.payload_len,
        &chunk.payload,
    );
    let header = ChunkHeader::new_raw_block_segment_authenticated(
        &chunk.header.block_hash,
        chunk.header.chunk_id,
        chunk.header.total_chunks,
        chunk.header.payload_len,
        hmac,
    );
    Chunk::new(header, chunk.payload.clone())
}

fn raw_block_header_hash(header: &[u8]) -> [u8; 32] {
    bedrock_forge::zcash_block_hash(header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bedrock_forge::RawBlockSegment;

    #[test]
    fn decode_hex_block_ignores_whitespace() {
        assert_eq!(decode_hex_block(" 00\nff ").unwrap(), vec![0x00, 0xff]);
    }

    #[test]
    fn authenticated_raw_segment_chunk_preserves_segment_message_type() {
        let raw_block = vec![0xab; ZCASH_FULL_HEADER_SIZE + 8];
        let block_hash = raw_block_header_hash(&raw_block[..ZCASH_FULL_HEADER_SIZE]);
        let segment = split_raw_block(block_hash, &raw_block, RawBlockSegment::HEADER_LEN + 16)
            .unwrap()
            .remove(0);
        let chunker = BlockChunker::new(10, 3).unwrap();
        let chunk = chunker
            .raw_block_segment_to_chunks(&segment)
            .unwrap()
            .remove(0);
        let session = RelaySession::new("127.0.0.1:0".parse().unwrap(), [0x42; 32]);

        let authenticated = authenticate_raw_segment_chunk(&session, &chunk);

        assert_eq!(authenticated.header.version, 2);
        assert_eq!(
            authenticated.header.msg_type,
            bedrock_forge::MessageType::RawBlockSegment
        );
        assert!(session.verify_hmac(
            &authenticated.header.block_hash,
            authenticated.header.chunk_id,
            authenticated.header.total_chunks,
            authenticated.header.payload_len,
            &authenticated.payload,
            &authenticated.header.hmac
        ));
    }
}
