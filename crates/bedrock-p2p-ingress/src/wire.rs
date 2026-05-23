use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{IngressError, Result};

pub const MAINNET_MAGIC: [u8; 4] = [0x24, 0xe9, 0x27, 0x64];
pub const DEFAULT_PORT: u16 = 8233;
pub const MAX_MESSAGE_LEN: usize = 2 * 1024 * 1024;
pub const MSG_TX: u32 = 1;
pub const MSG_BLOCK: u32 = 2;
pub const MSG_FILTERED_BLOCK: u32 = 3;
pub const MSG_WTX: u32 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub command: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Inventory {
    pub inv_type: u32,
    pub hash: [u8; 32],
    pub auth_digest: Option<[u8; 32]>,
}

impl Inventory {
    pub fn is_block(&self) -> bool {
        self.inv_type == MSG_BLOCK
    }

    pub fn is_transaction(&self) -> bool {
        matches!(self.inv_type, MSG_TX | MSG_WTX)
    }
}

pub async fn read_message<R>(reader: &mut R) -> Result<Message>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 24];
    reader.read_exact(&mut header).await?;

    if header[0..4] != MAINNET_MAGIC {
        return Err(IngressError::Wire(format!(
            "unexpected magic {}",
            hex::encode(&header[0..4])
        )));
    }

    let command = parse_command(&header[4..16])?;
    let len = u32::from_le_bytes(header[16..20].try_into().expect("slice length")) as usize;
    if len > MAX_MESSAGE_LEN {
        return Err(IngressError::Wire(format!("message too large: {len}")));
    }

    let checksum = &header[20..24];
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    let expected = checksum_bytes(&payload);
    if checksum != expected {
        return Err(IngressError::Wire(format!(
            "bad checksum for command {command}"
        )));
    }

    Ok(Message { command, payload })
}

pub async fn write_message<W>(writer: &mut W, command: &str, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if command.len() > 12 {
        return Err(IngressError::Wire(format!("command too long: {command}")));
    }
    if payload.len() > MAX_MESSAGE_LEN {
        return Err(IngressError::Wire(format!(
            "payload too large: {}",
            payload.len()
        )));
    }

    let mut header = Vec::with_capacity(24);
    header.extend_from_slice(&MAINNET_MAGIC);
    let mut command_bytes = [0u8; 12];
    command_bytes[..command.len()].copy_from_slice(command.as_bytes());
    header.extend_from_slice(&command_bytes);
    header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    header.extend_from_slice(&checksum_bytes(payload));

    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

pub fn checksum_bytes(payload: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&second[..4]);
    checksum
}

fn parse_command(bytes: &[u8]) -> Result<String> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end])
        .map(|s| s.to_string())
        .map_err(|e| IngressError::Wire(format!("invalid command utf8: {e}")))
}

pub fn encode_compact_size(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=252 => out.push(value as u8),
        253..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
}

pub fn decode_compact_size(payload: &[u8], cursor: &mut usize) -> Result<u64> {
    let first = read_u8(payload, cursor)?;
    match first {
        0..=252 => Ok(first as u64),
        0xfd => Ok(read_u16_le(payload, cursor)? as u64),
        0xfe => Ok(read_u32_le(payload, cursor)? as u64),
        0xff => Ok(read_u64_le(payload, cursor)?),
    }
}

pub fn encode_inventory(items: &[Inventory]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_compact_size(items.len() as u64, &mut out);
    for item in items {
        out.extend_from_slice(&item.inv_type.to_le_bytes());
        out.extend_from_slice(&item.hash);
        if item.inv_type == MSG_WTX {
            out.extend_from_slice(&item.auth_digest.unwrap_or([0u8; 32]));
        }
    }
    out
}

pub fn parse_inventory(payload: &[u8]) -> Result<Vec<Inventory>> {
    let mut cursor = 0;
    let count = decode_compact_size(payload, &mut cursor)?;
    if count > 50_000 {
        return Err(IngressError::Wire(format!(
            "too many inventory entries: {count}"
        )));
    }

    let mut items = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let inv_type = read_u32_le(payload, &mut cursor)?;
        let mut hash = [0u8; 32];
        read_exact(payload, &mut cursor, &mut hash)?;
        let auth_digest = if inv_type == MSG_WTX {
            let mut auth_digest = [0u8; 32];
            read_exact(payload, &mut cursor, &mut auth_digest)?;
            Some(auth_digest)
        } else if !matches!(inv_type, MSG_TX | MSG_BLOCK | MSG_FILTERED_BLOCK) {
            return Err(IngressError::Wire(format!(
                "unrecognized inventory type: {inv_type}"
            )));
        } else {
            None
        };
        items.push(Inventory {
            inv_type,
            hash,
            auth_digest,
        });
    }
    Ok(items)
}

pub fn parse_addr(payload: &[u8], max_count: usize) -> Result<Vec<SocketAddr>> {
    let mut cursor = 0;
    let count = decode_compact_size(payload, &mut cursor)?;
    if count as usize > max_count {
        return Err(IngressError::Wire(format!(
            "too many addr entries: {count}"
        )));
    }

    let mut peers = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let _timestamp = read_u32_le(payload, &mut cursor)?;
        let _services = read_u64_le(payload, &mut cursor)?;
        let mut ip_bytes = [0u8; 16];
        read_exact(payload, &mut cursor, &mut ip_bytes)?;
        let port = read_u16_be(payload, &mut cursor)?;
        if port == 0 {
            continue;
        }
        let ip = network_ip(ip_bytes);
        if skip_ip(ip) {
            continue;
        }
        peers.push(SocketAddr::new(ip, port));
    }
    Ok(peers)
}

fn network_ip(bytes: [u8; 16]) -> IpAddr {
    if bytes[..10] == [0u8; 10] && bytes[10..12] == [0xff, 0xff] {
        IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
    } else {
        IpAddr::V6(Ipv6Addr::from(bytes))
    }
}

fn skip_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_private()
                || ip.is_link_local()
        }
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
}

pub fn read_u8(payload: &[u8], cursor: &mut usize) -> Result<u8> {
    let value = *payload
        .get(*cursor)
        .ok_or_else(|| IngressError::Wire("unexpected end of payload".to_string()))?;
    *cursor += 1;
    Ok(value)
}

pub fn read_u16_le(payload: &[u8], cursor: &mut usize) -> Result<u16> {
    let bytes = read_array::<2>(payload, cursor)?;
    Ok(u16::from_le_bytes(bytes))
}

pub fn read_u16_be(payload: &[u8], cursor: &mut usize) -> Result<u16> {
    let bytes = read_array::<2>(payload, cursor)?;
    Ok(u16::from_be_bytes(bytes))
}

pub fn read_u32_le(payload: &[u8], cursor: &mut usize) -> Result<u32> {
    let bytes = read_array::<4>(payload, cursor)?;
    Ok(u32::from_le_bytes(bytes))
}

pub fn read_u64_le(payload: &[u8], cursor: &mut usize) -> Result<u64> {
    let bytes = read_array::<8>(payload, cursor)?;
    Ok(u64::from_le_bytes(bytes))
}

pub fn read_i32_le(payload: &[u8], cursor: &mut usize) -> Result<i32> {
    let bytes = read_array::<4>(payload, cursor)?;
    Ok(i32::from_le_bytes(bytes))
}

pub fn read_exact(payload: &[u8], cursor: &mut usize, out: &mut [u8]) -> Result<()> {
    let end = cursor
        .checked_add(out.len())
        .ok_or_else(|| IngressError::Wire("cursor overflow".to_string()))?;
    let bytes = payload
        .get(*cursor..end)
        .ok_or_else(|| IngressError::Wire("unexpected end of payload".to_string()))?;
    out.copy_from_slice(bytes);
    *cursor = end;
    Ok(())
}

fn read_array<const N: usize>(payload: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    read_exact(payload, cursor, &mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrips_message_frame() {
        let (mut a, mut b) = duplex(1024);
        write_message(&mut a, "ping", &[1, 2, 3, 4]).await.unwrap();
        let msg = read_message(&mut b).await.unwrap();
        assert_eq!(msg.command, "ping");
        assert_eq!(msg.payload, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn rejects_bad_checksum() {
        let (mut a, mut b) = duplex(1024);
        let mut header = Vec::new();
        header.extend_from_slice(&MAINNET_MAGIC);
        header.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
        header.extend_from_slice(&1u32.to_le_bytes());
        header.extend_from_slice(&[0, 0, 0, 0]);
        a.write_all(&header).await.unwrap();
        a.write_all(&[1]).await.unwrap();
        let err = read_message(&mut b).await.unwrap_err();
        assert!(matches!(err, IngressError::Wire(_)));
    }

    #[test]
    fn compact_size_roundtrip() {
        for value in [0, 252, 253, 65_535, 65_536, u32::MAX as u64 + 1] {
            let mut encoded = Vec::new();
            encode_compact_size(value, &mut encoded);
            let mut cursor = 0;
            assert_eq!(decode_compact_size(&encoded, &mut cursor).unwrap(), value);
            assert_eq!(cursor, encoded.len());
        }
    }

    #[test]
    fn inventory_roundtrip() {
        let item = Inventory {
            inv_type: MSG_BLOCK,
            hash: [0xab; 32],
            auth_digest: None,
        };
        let payload = encode_inventory(&[item]);
        let parsed = parse_inventory(&payload).unwrap();
        assert_eq!(parsed, vec![item]);
    }

    #[test]
    fn wtx_inventory_roundtrip_preserves_auth_digest() {
        let item = Inventory {
            inv_type: MSG_WTX,
            hash: [0xaa; 32],
            auth_digest: Some([0xbb; 32]),
        };

        let payload = encode_inventory(&[item]);
        let parsed = parse_inventory(&payload).unwrap();

        assert_eq!(parsed, vec![item]);
    }

    #[test]
    fn parses_mixed_wtx_and_block_inventory() {
        let mut payload = Vec::new();
        encode_compact_size(2, &mut payload);
        payload.extend_from_slice(&MSG_WTX.to_le_bytes());
        payload.extend_from_slice(&[0xaa; 32]);
        payload.extend_from_slice(&[0xbb; 32]);
        payload.extend_from_slice(&MSG_BLOCK.to_le_bytes());
        payload.extend_from_slice(&[0xcc; 32]);
        let parsed = parse_inventory(&payload).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].inv_type, MSG_WTX);
        assert_eq!(parsed[0].auth_digest, Some([0xbb; 32]));
        assert_eq!(parsed[1].inv_type, MSG_BLOCK);
    }

    #[test]
    fn parses_addr_payload() {
        let mut payload = Vec::new();
        encode_compact_size(2, &mut payload);

        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&[0; 10]);
        payload.extend_from_slice(&[0xff, 0xff]);
        payload.extend_from_slice(&[8, 8, 8, 8]);
        payload.extend_from_slice(&8233u16.to_be_bytes());

        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&[0; 10]);
        payload.extend_from_slice(&[0xff, 0xff]);
        payload.extend_from_slice(&[10, 0, 0, 1]);
        payload.extend_from_slice(&8233u16.to_be_bytes());

        let parsed = parse_addr(&payload, 10).unwrap();
        assert_eq!(parsed, vec!["8.8.8.8:8233".parse().unwrap()]);
    }
}
