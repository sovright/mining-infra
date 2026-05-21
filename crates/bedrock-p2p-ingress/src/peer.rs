use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info};

use crate::config::Config;
use crate::error::{IngressError, Result};
use crate::event::EventSink;
use crate::forge::ForgeBridge;
use crate::hash::{display_hash_from_header, inventory_hash_to_display};
use crate::wire::{
    Inventory, encode_compact_size, encode_inventory, parse_inventory, read_i32_le, read_message,
    write_message,
};

const PROTOCOL_VERSION: i32 = 170_140;
const USER_AGENT: &str = "/bedrock-p2p-ingress:0.1.0/";

pub async fn run_peer(
    peer_addr: SocketAddr,
    config: Config,
    events: EventSink,
    forge: Option<ForgeBridge>,
) -> Result<()> {
    let peer = peer_addr.to_string();
    let stream = timeout(config.connect_timeout, TcpStream::connect(peer_addr))
        .await
        .map_err(|_| IngressError::Timeout(format!("connect to {peer}")))??;
    stream.set_nodelay(true)?;
    events.p2p_peer_connected(&peer)?;
    info!(%peer, "connected to Zcash P2P peer");

    let (mut reader, mut writer) = stream.into_split();
    let version = version_payload(peer_addr);
    write_message(&mut writer, "version", &version).await?;

    let mut saw_verack = false;
    let mut sent_verack = false;
    let mut seen_inv = HashSet::new();
    let mut requested = HashSet::new();

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
                if !sent_verack {
                    write_message(&mut writer, "verack", &[]).await?;
                    sent_verack = true;
                }
            }
            "verack" => {
                saw_verack = true;
                events.p2p_handshake_complete(&peer)?;
                write_message(&mut writer, "getaddr", &[]).await?;
            }
            "reject" => {
                events.p2p_reject(&peer, msg.payload.len())?;
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
                        block_requests.push(inv);
                    }
                }
                if !block_requests.is_empty() {
                    let request = encode_inventory(&block_requests);
                    write_message(&mut writer, "getdata", &request).await?;
                }
            }
            "block" => {
                if !saw_verack {
                    continue;
                }
                let display = display_hash_from_header(&msg.payload)?;
                events.p2p_block_received(&peer, &display, msg.payload.len())?;
                if let Some(forge) = &forge {
                    if let Err(error) = forge.forward_header_only(&msg.payload).await {
                        events.p2p_peer_error(&peer, &format!("forge forward failed: {error}"))?;
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
    fn network_addr_encodes_ipv4_mapped_ipv6() {
        let mut out = Vec::new();
        encode_network_address("1.2.3.4:8233".parse().unwrap(), &mut out);
        assert_eq!(&out[8..20], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
        assert_eq!(&out[20..24], &[1, 2, 3, 4]);
        assert_eq!(&out[24..26], &8233u16.to_be_bytes());
    }
}
