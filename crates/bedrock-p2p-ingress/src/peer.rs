use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info};

use crate::config::Config;
use crate::crawler::Crawler;
use crate::error::{IngressError, Result};
use crate::event::EventSink;
use crate::forge::ForgeBridge;
use crate::hash::{display_hash_from_header, inventory_hash_to_display};
use crate::wire::{
    Inventory, encode_compact_size, encode_inventory, parse_addr, parse_inventory, read_i32_le,
    read_message, write_message,
};

const PROTOCOL_VERSION: i32 = 170_140;
const MIN_ACCEPTABLE_REMOTE_VERSION: i32 = 170_120;
const USER_AGENT: &str = "/bedrock-p2p-ingress:0.1.0/";

pub async fn run_peer(
    peer_addr: SocketAddr,
    config: Config,
    events: EventSink,
    forge: Option<ForgeBridge>,
    crawler: Crawler,
) -> Result<()> {
    let peer = peer_addr.to_string();
    let connect_started = Instant::now();
    let stream = timeout(config.connect_timeout, TcpStream::connect(peer_addr))
        .await
        .map_err(|_| IngressError::Timeout(format!("connect to {peer}")))??;
    events.p2p_connect_timing(&peer, connect_started.elapsed().as_millis())?;
    stream.set_nodelay(true)?;
    events.p2p_peer_connected(&peer)?;
    info!(%peer, "connected to Zcash P2P peer");

    let (mut reader, mut writer) = stream.into_split();
    let version = version_payload(peer_addr);
    write_message(&mut writer, "version", &version).await?;

    let mut saw_verack = false;
    let mut sent_verack = false;
    let handshake_started = Instant::now();
    let mut ping_nonce = None;
    let mut ping_started = None;
    let mut seen_inv = HashSet::new();
    let mut requested = HashSet::new();
    let mut pending_block_responses = VecDeque::new();

    loop {
        let msg = timeout(Duration::from_secs(90), read_message(&mut reader))
            .await
            .map_err(|_| IngressError::Timeout(format!("read from {peer}")))??;
        debug!(%peer, command = %msg.command, bytes = msg.payload.len(), "received P2P message");

        match msg.command.as_str() {
            "version" => {
                let remote_version = remote_version(&msg.payload).unwrap_or_default();
                info!(%peer, remote_version, "received version");
                events.p2p_peer_version(&peer, remote_version)?;
                if !is_acceptable_remote_version(remote_version) {
                    return Err(IngressError::Wire(format!(
                        "remote protocol version too old: {remote_version} < {MIN_ACCEPTABLE_REMOTE_VERSION}"
                    )));
                }
                if !sent_verack {
                    write_message(&mut writer, "verack", &[]).await?;
                    sent_verack = true;
                }
            }
            "verack" => {
                saw_verack = true;
                events.p2p_handshake_complete(&peer)?;
                events.p2p_handshake_timing(&peer, handshake_started.elapsed().as_millis())?;
                let nonce = nonce();
                write_message(&mut writer, "ping", &nonce.to_le_bytes()).await?;
                ping_nonce = Some(nonce);
                ping_started = Some(Instant::now());
                write_message(&mut writer, "getaddr", &[]).await?;
            }
            "reject" => {
                events.p2p_reject(&peer, msg.payload.len())?;
            }
            "addr" => {
                if !saw_verack {
                    continue;
                }
                let addrs = parse_addr(&msg.payload, config.crawler_max_addr_per_message)?;
                let count = addrs.len();
                let accepted = crawler.add_discovered(&peer, addrs, &events)?;
                events.p2p_addr_received(&peer, count, accepted)?;
            }
            "pong" => {
                if let Some(nonce) = pong_nonce(&msg.payload)
                    && Some(nonce) == ping_nonce
                {
                    if let Some(started) = ping_started.take() {
                        events.p2p_ping_rtt(&peer, nonce, started.elapsed().as_millis())?;
                    }
                    ping_nonce = None;
                }
            }
            "ping" => {
                write_message(&mut writer, "pong", &msg.payload).await?;
            }
            "inv" => {
                if !saw_verack {
                    continue;
                }
                let invs = parse_inventory(&msg.payload)?;
                let mut block_requests = Vec::new();
                for inv in invs.into_iter().filter(Inventory::is_block) {
                    if !seen_inv.insert(inv.hash) {
                        continue;
                    }
                    let display = inventory_hash_to_display(&inv.hash);
                    events.p2p_block_inv(&peer, &display)?;
                    if requested.insert(inv.hash) {
                        pending_block_responses.push_back(inv.hash);
                        block_requests.push(inv);
                    }
                }
                if !block_requests.is_empty() {
                    let requested_hashes: Vec<String> = block_requests
                        .iter()
                        .map(|inv| inventory_hash_to_display(&inv.hash))
                        .collect();
                    let request = encode_inventory(&block_requests);
                    write_message(&mut writer, "getdata", &request).await?;
                    for hash in requested_hashes {
                        events.p2p_getdata_sent(&peer, &hash)?;
                    }
                }
            }
            "block" => {
                if !saw_verack {
                    continue;
                }
                let display =
                    received_block_display_hash(&mut pending_block_responses, &msg.payload)?;
                events.p2p_block_received(&peer, &display, msg.payload.len())?;
                if let Some(forge) = &forge {
                    match forge.forward_block(&msg.payload).await {
                        Ok(forwarded) => {
                            events.p2p_forge_block_forwarded(
                                &peer,
                                &display,
                                forwarded.bytes,
                                forwarded.tx_count,
                            )?;
                        }
                        Err(error) => {
                            events
                                .p2p_peer_error(&peer, &format!("forge forward failed: {error}"))?;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn remote_version(payload: &[u8]) -> Result<i32> {
    let mut cursor = 0;
    read_i32_le(payload, &mut cursor)
}

fn is_acceptable_remote_version(remote_version: i32) -> bool {
    remote_version >= MIN_ACCEPTABLE_REMOTE_VERSION
}

fn pong_nonce(payload: &[u8]) -> Option<u64> {
    if payload.len() == 8 {
        Some(u64::from_le_bytes(payload.try_into().ok()?))
    } else {
        None
    }
}

fn received_block_display_hash(
    pending_block_responses: &mut VecDeque<[u8; 32]>,
    block_payload: &[u8],
) -> Result<String> {
    if let Some(hash) = pending_block_responses.pop_front() {
        return Ok(inventory_hash_to_display(&hash));
    }

    display_hash_from_header(block_payload)
}

fn version_payload(peer_addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&(unix_time_secs() as i64).to_le_bytes());
    encode_network_address(peer_addr, &mut out);
    encode_network_address(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        &mut out,
    );
    out.extend_from_slice(&nonce().to_le_bytes());
    encode_var_str(USER_AGENT, &mut out);
    out.extend_from_slice(&0i32.to_le_bytes());
    out.push(0);
    out
}

fn encode_network_address(addr: SocketAddr, out: &mut Vec<u8>) {
    out.extend_from_slice(&0u64.to_le_bytes());
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.extend_from_slice(&[0; 10]);
            out.extend_from_slice(&[0xff, 0xff]);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

fn encode_var_str(value: &str, out: &mut Vec<u8>) {
    encode_compact_size(value.len() as u64, out);
    out.extend_from_slice(value.as_bytes());
}

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn nonce() -> u64 {
    let pid = std::process::id() as u64;
    unix_time_secs().rotate_left(17) ^ pid ^ 0xbed0_c202_6052_1001
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_payload_contains_user_agent() {
        let payload = version_payload("127.0.0.1:8233".parse().unwrap());
        assert!(
            payload
                .windows(USER_AGENT.len())
                .any(|w| w == USER_AGENT.as_bytes())
        );
    }

    #[test]
    fn rejects_remote_versions_below_zcash_mainnet_floor() {
        assert!(!is_acceptable_remote_version(170_020));
        assert!(!is_acceptable_remote_version(170_119));
        assert!(is_acceptable_remote_version(170_120));
        assert!(is_acceptable_remote_version(PROTOCOL_VERSION));
    }

    #[test]
    fn network_addr_encodes_ipv4_mapped_ipv6() {
        let mut out = Vec::new();
        encode_network_address("1.2.3.4:8233".parse().unwrap(), &mut out);
        assert_eq!(&out[8..20], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
        assert_eq!(&out[20..24], &[1, 2, 3, 4]);
        assert_eq!(&out[24..26], &8233u16.to_be_bytes());
    }

    #[test]
    fn received_block_display_uses_requested_inventory_hash() {
        let mut pending = std::collections::VecDeque::new();
        let mut hash = [0u8; 32];
        hash[0] = 0x5c;
        hash[31] = 0x01;
        pending.push_back(hash);

        let display = received_block_display_hash(&mut pending, &[0u8; 4]).unwrap();

        assert!(display.starts_with("01"));
        assert!(display.ends_with("5c"));
        assert!(pending.is_empty());
    }

    #[test]
    fn parses_pong_nonce() {
        let nonce = 42u64;
        assert_eq!(pong_nonce(&nonce.to_le_bytes()), Some(42));
        assert_eq!(pong_nonce(&[1, 2, 3]), None);
    }
}
