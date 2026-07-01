use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::crawler::Crawler;
use crate::error::{IngressError, Result};
use crate::event::EventSink;
use crate::hash::{inventory_hash_to_display, raw_hash_from_header};
use crate::relay_bridge::RelayBridge;
use crate::tx_cache::{TxCache, TxInventoryKey};
use crate::tx_feed::TxFeedClient;
use crate::wire::{
    Inventory, encode_compact_size, encode_inventory, parse_addr, parse_inventory, read_i32_le,
    read_message, write_message,
};

// Zcash protocol version sent in our `version` message. NU6.2 activated
// on mainnet at block 3,370,884 (2026-04). Zebra 5.0.0 ships 170_150 as its
// current `protocolversion`; remote NU6.2 peers drop connections from nodes
// reporting older versions. Keep this in sync with the latest mainnet
// network upgrade as new ones land.
const PROTOCOL_VERSION: i32 = 170_150;

// Floor for accepting *remote* version messages. We stay permissive here so
// the ingress can still ingest from slower-to-upgrade peers and from
// post-NU5/NU6 nodes that haven't moved to NU6.2 yet.
const MIN_ACCEPTABLE_REMOTE_VERSION: i32 = 170_120;

// Sub-version sent in our `version` message. Zcash mainnet currently
// accepts any non-banned user agent; we keep this short and identifying.
const USER_AGENT: &str = "/sovright-p2p-ingress:0.2.0/";

pub async fn run_peer(
    peer_addr: SocketAddr,
    config: Config,
    events: EventSink,
    relay: Option<RelayBridge>,
    tx_cache: Option<TxCache>,
    tx_feed: Option<TxFeedClient>,
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
    let mut seen_tx_inv = HashSet::new();
    let mut requested_tx = HashSet::new();
    let mut pending_tx_responses = VecDeque::new();

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
                let mut tx_requests = Vec::new();
                for inv in invs {
                    if inv.is_block() {
                        if !seen_inv.insert(inv.hash) {
                            continue;
                        }
                        let display = inventory_hash_to_display(&inv.hash);
                        events.p2p_block_inv(&peer, &display)?;
                        crawler.score_peer(
                            peer_addr,
                            config.peer_score_block_inv,
                            "block_inv",
                            &events,
                        )?;
                        if requested.insert(inv.hash) {
                            pending_block_responses.push_back(inv.hash);
                            block_requests.push(inv);
                        }
                    } else if inv.is_transaction()
                        && let Some(key) = queue_tx_request(
                            inv,
                            tx_cache.is_some() || tx_feed.is_some(),
                            config.tx_request_limit_per_inv,
                            &mut seen_tx_inv,
                            &mut requested_tx,
                            &mut pending_tx_responses,
                            &mut tx_requests,
                        )
                    {
                        events.p2p_tx_inv(&peer, key.kind(), &key.display_hash())?;
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
                if !tx_requests.is_empty() {
                    let requested_keys: Vec<TxInventoryKey> = tx_requests
                        .iter()
                        .filter_map(TxInventoryKey::from_inventory)
                        .collect();
                    let request = encode_inventory(&tx_requests);
                    write_message(&mut writer, "getdata", &request).await?;
                    for key in requested_keys {
                        events.p2p_tx_getdata_sent(&peer, key.kind(), &key.display_hash())?;
                    }
                }
            }
            "block" => {
                if !saw_verack {
                    continue;
                }
                let display =
                    received_block_display_hash(&mut pending_block_responses, &msg.payload)?;
                let consensus_hash = msg
                    .payload
                    .get(..sovright_relay::ZCASH_FULL_HEADER_SIZE)
                    .map(|header| sovright_relay::consensus_block_hash_display(header))
                    .unwrap_or_default();
                events.p2p_block_received(&peer, &display, &consensus_hash, msg.payload.len())?;
                crawler.score_peer(
                    peer_addr,
                    config.peer_score_block_received,
                    "block_received",
                    &events,
                )?;
                if let Some(relay) = &relay {
                    match relay.forward_block(&msg.payload, tx_cache.as_ref()).await {
                        Ok(forwarded) => {
                            events.p2p_relay_block_forwarded(
                                &peer,
                                &display,
                                forwarded.bytes,
                                forwarded.tx_count,
                                forwarded.mode.as_str(),
                                forwarded.relay_objects,
                            )?;
                            crawler.score_peer(
                                peer_addr,
                                config.peer_score_relay_forwarded,
                                "relay_forwarded",
                                &events,
                            )?;
                        }
                        Err(error) => {
                            events
                                .p2p_peer_error(&peer, &format!("relay forward failed: {error}"))?;
                        }
                    }
                }
            }
            "tx" => {
                if !saw_verack {
                    continue;
                }
                if let Some(key) = pending_tx_responses.pop_front() {
                    let wtxid = key.to_wtxid();
                    if let Some(cache) = &tx_cache {
                        let outcome = cache.insert(wtxid, msg.payload.clone());
                        events.p2p_tx_received(
                            &peer,
                            key.kind(),
                            &key.display_hash(),
                            msg.payload.len(),
                            outcome.entries,
                            outcome.bytes,
                            outcome.evicted_entries,
                            outcome.evicted_bytes,
                            outcome.dropped_too_large,
                        )?;
                        emit_tx_cache_snapshot(&events, cache)?;
                    }
                    if let Some(feed) = &tx_feed {
                        match feed.send(wtxid, &msg.payload).await {
                            Ok(()) => events.p2p_tx_feed_forwarded(
                                &peer,
                                key.kind(),
                                &key.display_hash(),
                                msg.payload.len(),
                            )?,
                            Err(error) => events.p2p_peer_error(
                                &peer,
                                &format!("tx feed forward failed: {error}"),
                            )?,
                        }
                    }
                } else if tx_cache.is_some() || tx_feed.is_some() {
                    events
                        .p2p_peer_error(&peer, "received tx without pending transaction request")?;
                }
            }
            _ => {}
        }
    }
}

fn emit_tx_cache_snapshot(events: &EventSink, cache: &TxCache) -> Result<()> {
    let snapshot = cache.snapshot();
    events.p2p_tx_cache_snapshot(
        snapshot.entries,
        snapshot.bytes,
        snapshot.max_entries,
        snapshot.max_bytes,
        snapshot.max_tx_bytes,
        snapshot.evicted_entries_total,
        snapshot.evicted_bytes_total,
        snapshot.dropped_too_large_total,
    )
}

fn queue_tx_request(
    inv: Inventory,
    tx_cache_enabled: bool,
    request_limit: usize,
    seen: &mut HashSet<TxInventoryKey>,
    requested: &mut HashSet<TxInventoryKey>,
    pending: &mut VecDeque<TxInventoryKey>,
    requests: &mut Vec<Inventory>,
) -> Option<TxInventoryKey> {
    if !tx_cache_enabled || requests.len() >= request_limit {
        return None;
    }
    let key = TxInventoryKey::from_inventory(&inv)?;
    if !seen.insert(key) {
        return None;
    }
    if requested.insert(key) {
        pending.push_back(key);
        requests.push(key.to_inventory());
        Some(key)
    } else {
        None
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
    let actual_inventory_hash = raw_hash_from_header(block_payload)?;
    let actual_hash = inventory_hash_to_display(&actual_inventory_hash);
    if let Some(index) = pending_block_responses
        .iter()
        .position(|hash| *hash == actual_inventory_hash)
    {
        pending_block_responses.remove(index);
        if index != 0 {
            warn!(
                actual_hash,
                pending_index = index,
                "Received requested block out of order"
            );
        }
        return Ok(actual_hash);
    }

    if let Some(hash) = pending_block_responses.front() {
        let requested_hash = inventory_hash_to_display(hash);
        warn!(
            requested_hash,
            actual_hash, "Received block hash did not match any pending requested inventory hash"
        );
    }

    Ok(actual_hash)
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
    use crate::hash::display_hash_from_header;
    use crate::tx_cache::TxInventoryKey;
    use crate::wire::{MSG_TX, MSG_WTX};
    use std::fs;

    fn temp_log_path(name: &str) -> std::path::PathBuf {
        let unique = format!(
            "sovright-p2p-peer-{name}-{}-{}.jsonl",
            std::process::id(),
            unix_time_secs()
        );
        std::env::temp_dir().join(unique)
    }

    fn inventory_hash_from_display(display: &str) -> [u8; 32] {
        let mut bytes: Vec<u8> = hex::decode(display).unwrap();
        bytes.reverse();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

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
    fn received_block_display_uses_actual_header_hash_when_pending_mismatches() {
        let mut pending = VecDeque::new();
        let mut hash = [0u8; 32];
        hash[0] = 0x5c;
        hash[31] = 0x01;
        pending.push_back(hash);
        let block_payload = vec![0u8; sovright_relay::ZCASH_FULL_HEADER_SIZE];
        let expected = display_hash_from_header(&block_payload).unwrap();

        let display = received_block_display_hash(&mut pending, &block_payload).unwrap();

        assert_eq!(display, expected);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], hash);
    }

    #[test]
    fn received_block_display_removes_matching_out_of_order_pending_hash() {
        let mut pending = VecDeque::new();
        pending.push_back([0x5c; 32]);

        let block_payload = vec![0u8; sovright_relay::ZCASH_FULL_HEADER_SIZE];
        let actual_display = display_hash_from_header(&block_payload).unwrap();
        let actual_inventory = inventory_hash_from_display(&actual_display);
        pending.push_back(actual_inventory);

        let display = received_block_display_hash(&mut pending, &block_payload).unwrap();

        assert_eq!(display, actual_display);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], [0x5c; 32]);
    }

    #[test]
    fn received_block_display_falls_back_to_payload_header_hash_without_pending_request() {
        let mut pending = VecDeque::new();
        let block_payload = vec![0u8; sovright_relay::ZCASH_FULL_HEADER_SIZE];
        let expected = display_hash_from_header(&block_payload).unwrap();

        let display = received_block_display_hash(&mut pending, &block_payload).unwrap();

        assert_eq!(display, expected);
    }

    #[test]
    fn parses_pong_nonce() {
        let nonce = 42u64;
        assert_eq!(pong_nonce(&nonce.to_le_bytes()), Some(42));
        assert_eq!(pong_nonce(&[1, 2, 3]), None);
    }

    #[test]
    fn queues_transaction_inventory_for_getdata_when_cache_enabled() {
        let inv = Inventory {
            inv_type: MSG_WTX,
            hash: [0x11; 32],
            auth_digest: Some([0x22; 32]),
        };
        let mut seen = HashSet::new();
        let mut requested = HashSet::new();
        let mut pending = VecDeque::new();
        let mut requests = Vec::new();

        let queued = queue_tx_request(
            inv,
            true,
            1,
            &mut seen,
            &mut requested,
            &mut pending,
            &mut requests,
        );

        let key = TxInventoryKey::wtx([0x11; 32], [0x22; 32]);
        assert_eq!(queued, Some(key));
        assert!(seen.contains(&key));
        assert!(requested.contains(&key));
        assert_eq!(pending.pop_front(), Some(key));
        assert_eq!(requests, vec![inv]);
    }

    #[test]
    fn skips_transaction_inventory_when_cache_disabled_or_limit_reached() {
        let inv = Inventory {
            inv_type: MSG_TX,
            hash: [0x33; 32],
            auth_digest: None,
        };
        let mut seen = HashSet::new();
        let mut requested = HashSet::new();
        let mut pending = VecDeque::new();
        let mut requests = Vec::new();

        assert_eq!(
            queue_tx_request(
                inv,
                false,
                1,
                &mut seen,
                &mut requested,
                &mut pending,
                &mut requests,
            ),
            None
        );
        assert_eq!(
            queue_tx_request(
                inv,
                true,
                0,
                &mut seen,
                &mut requested,
                &mut pending,
                &mut requests,
            ),
            None
        );
    }

    #[test]
    fn emits_tx_cache_snapshot_event_from_cache_state() {
        let path = temp_log_path("tx-cache-snapshot");
        let events = EventSink::new(Some(path.clone())).unwrap();
        let cache = TxCache::new(crate::tx_cache::TxCacheConfig {
            max_entries: 8,
            max_bytes: 1_024,
            max_tx_bytes: 512,
        });
        cache.insert(TxInventoryKey::tx([0x91; 32]).to_wtxid(), vec![1, 2, 3]);

        emit_tx_cache_snapshot(&events, &cache).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let row: serde_json::Value =
            serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(row["event"], "p2p_tx_cache_snapshot");
        assert_eq!(row["entries"], 1);
        assert_eq!(row["bytes"], 3);
        assert_eq!(row["max_entries"], 8);
        assert_eq!(row["max_bytes"], 1_024);
        assert_eq!(row["max_tx_bytes"], 512);

        let _ = fs::remove_file(path);
    }
}
