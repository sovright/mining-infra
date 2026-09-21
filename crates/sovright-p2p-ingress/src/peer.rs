use std::collections::{HashSet, VecDeque};
use std::hash::Hash;
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
use crate::wtxid::{SOVRIGHT_P2P_CONSENSUS_BRANCH_ID, wtxid_from_tx_bytes};
use sovright_relay::WtxId;

// Zcash protocol version sent in our `version` message. NU6.3/Ironwood activated
// on mainnet at block 3,428,143 (2026-07-28); zebrad 6.2.3 reports 170_160 as its
// `protocolversion`. Post-upgrade peers complete the handshake with a node
// advertising an older version and then relay NOTHING to it -- at Ironwood this
// silently cut block ingest to ~zero for ~6h while every service still looked
// healthy. MUST be bumped as part of every network upgrade; the authoritative
// value is `getnetworkinfo.protocolversion` from an upgraded zebrad, never an
// inference from observed peer versions.
// See advertised_protocol_version_matches_current_network_upgrade().
const PROTOCOL_VERSION: i32 = 170_160;

// Floor for accepting *remote* version messages. We stay permissive here so
// the ingress can still ingest from slower-to-upgrade peers and from
// post-NU5/NU6 nodes that haven't moved to NU6.2 yet.
const MIN_ACCEPTABLE_REMOTE_VERSION: i32 = 170_120;

// Advertising less than we demand of peers would be incoherent; enforce at
// compile time so a future upgrade cannot raise the floor past what we send.
const _: () = assert!(PROTOCOL_VERSION >= MIN_ACCEPTABLE_REMOTE_VERSION);

// Sub-version sent in our `version` message. Zcash mainnet currently
// accepts any non-banned user agent; we keep this short and identifying.
const USER_AGENT: &str = "/sovright-p2p-ingress:0.2.0/";

/// A bounded insertion-order cache. Duplicate sightings do not allocate an
/// extra queue entry or keep an old item alive indefinitely.
struct RecentInventory<K> {
    keys: HashSet<K>,
    order: VecDeque<K>,
    limit: usize,
}

impl<K: Copy + Eq + Hash> RecentInventory<K> {
    fn new(limit: usize) -> Self {
        Self {
            keys: HashSet::new(),
            order: VecDeque::new(),
            limit,
        }
    }

    fn insert(&mut self, key: K) -> bool {
        if self.keys.contains(&key) {
            return false;
        }
        if self.limit > 0 {
            if self.order.len() == self.limit {
                self.keys
                    .remove(&self.order.pop_front().expect("nonempty cache"));
            }
            self.keys.insert(key);
            self.order.push_back(key);
        }
        true
    }
}

/// Per-connection request state. Rejected inventories are never queued, and
/// only completed requests enter the bounded recent cache. A timeout or
/// notfound therefore permits retry without leaving lifetime history behind.
struct RequestWindow<K> {
    pending: VecDeque<(K, Instant)>,
    recent: RecentInventory<K>,
    limit: usize,
    timeout: Duration,
}

impl<K: Copy + Eq + Hash> RequestWindow<K> {
    fn new(limit: usize, recent_limit: usize, timeout: Duration) -> Self {
        Self {
            pending: VecDeque::new(),
            recent: RecentInventory::new(recent_limit),
            limit,
            timeout,
        }
    }

    fn admit(&mut self, key: K, now: Instant) -> bool {
        if self.pending.len() >= self.limit
            || self.recent.keys.contains(&key)
            || self.pending.iter().any(|(pending, _)| *pending == key)
        {
            return false;
        }
        self.pending.push_back((key, now + self.timeout));
        true
    }

    fn remove(&mut self, key: K) -> Option<usize> {
        let index = self
            .pending
            .iter()
            .position(|(pending, _)| *pending == key)?;
        self.pending.remove(index);
        Some(index)
    }

    fn complete(&mut self, key: K) -> Option<usize> {
        let index = self.remove(key)?;
        self.recent.insert(key);
        Some(index)
    }

    fn deadline(&self) -> Option<Instant> {
        self.pending.front().map(|(_, deadline)| *deadline)
    }

    fn expire(&mut self, now: Instant) {
        while self.deadline().is_some_and(|deadline| deadline <= now) {
            self.pending.pop_front();
        }
    }
}

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
    let limits = &config.inventory_limits;
    let mut seen_inv = RecentInventory::new(limits.recent_entries);
    let mut blocks = RequestWindow::new(limits.blocks, limits.recent_entries, limits.timeout);
    let mut transactions =
        RequestWindow::new(limits.transactions, limits.recent_entries, limits.timeout);

    loop {
        // Keep the same read future alive across expiry. Cancelling a partial
        // frame read on each deadline would desynchronise the wire decoder.
        let read = timeout(Duration::from_secs(90), read_message(&mut reader));
        tokio::pin!(read);
        let msg = loop {
            let deadline = blocks
                .deadline()
                .into_iter()
                .chain(transactions.deadline())
                .min();
            tokio::select! {
                result = &mut read => break result
                    .map_err(|_| IngressError::Timeout(format!("read from {peer}")))??,
                _ = async {
                    match deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let now = Instant::now();
                    blocks.expire(now);
                    transactions.expire(now);
                }
            }
        };
        let now = Instant::now();
        blocks.expire(now);
        transactions.expire(now);
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
                        if seen_inv.insert(inv.hash) {
                            let display = inventory_hash_to_display(&inv.hash);
                            events.p2p_block_inv(&peer, &display)?;
                            // Announcement rank remains independent of request
                            // capacity; the crawler also deduplicates awards.
                            crawler.score_block_announcement(peer_addr, inv.hash, &events)?;
                        }
                        if blocks.admit(inv.hash, now) {
                            block_requests.push(inv);
                        }
                    } else if inv.is_transaction()
                        && let Some(key) = queue_tx_request(
                            inv,
                            tx_cache.is_some() || tx_feed.is_some(),
                            config.tx_request_limit_per_inv,
                            &mut transactions,
                            &mut tx_requests,
                            now,
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
            "notfound" => {
                if !saw_verack {
                    continue;
                }
                for inv in parse_inventory(&msg.payload)? {
                    if inv.is_block() {
                        blocks.remove(inv.hash);
                    } else if let Some(key) = TxInventoryKey::from_inventory(&inv) {
                        transactions.remove(key);
                    }
                }
            }
            "block" => {
                if !saw_verack {
                    continue;
                }
                let display = received_block_display_hash(&mut blocks, &msg.payload)?;
                let consensus_hash = msg
                    .payload
                    .get(..sovright_relay::ZCASH_FULL_HEADER_SIZE)
                    .map(sovright_relay::consensus_block_hash_display)
                    .unwrap_or_default();
                // Best-effort: capture the coinbase miner payout script and the
                // pool tag at hear-time. A None never blocks the forward below.
                let miner_script = crate::coinbase::coinbase_miner_script(&msg.payload);
                let miner_tag = crate::coinbase::coinbase_text(&msg.payload);
                events.p2p_block_received(
                    &peer,
                    &display,
                    &consensus_hash,
                    msg.payload.len(),
                    miner_script.as_deref(),
                    miner_tag.as_deref(),
                )?;
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
                if let Some(wtxid) = wtxid_for_received_tx(&mut transactions, &msg.payload) {
                    let key = TxInventoryKey::from_wtxid(&wtxid);
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
                    // Pre-v5 or malformed: no derivable wtxid, so there is no
                    // honest key. Caching it under the queue's guess is what
                    // corrupted the cache in the first place.
                    events
                        .p2p_peer_error(&peer, "received tx with no derivable wtxid; not cached")?;
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
    window: &mut RequestWindow<TxInventoryKey>,
    requests: &mut Vec<Inventory>,
    now: Instant,
) -> Option<TxInventoryKey> {
    if !tx_cache_enabled || requests.len() >= request_limit {
        return None;
    }
    let key = TxInventoryKey::from_inventory(&inv)?;
    if window.admit(key, now) {
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

/// The wtxid to cache an incoming `tx` payload under.
///
/// The P2P protocol makes NO promise that a peer answers `getdata` in request
/// order: it may reorder freely, and it may silently omit a transaction it no
/// longer holds (with or without `notfound`). Popping the front of the pending
/// queue therefore assumes something the wire never guarantees, and a single
/// reorder or omission desynchronises the queue PERMANENTLY -- every later
/// transaction is then cached under some earlier request's wtxid.
///
/// That is not hypothetical: it put ~74% of compact reconstructions on the
/// wrong transactions, because the short_ids resolved perfectly to wtxids whose
/// cached bytes belonged to a different transaction entirely.
///
/// So derive the key from the payload itself, exactly as the block path already
/// does with the header hash. The queue then only records that a request is
/// outstanding; it never decides identity.
///
/// Returns `None` for pre-v5 transactions (no auth digest, so no derivable
/// wtxid) and for anything malformed. Those are NOT cached: a guessed key is
/// worse than a cache miss, which merely costs a getblocktxn round trip. The
/// sidecar's own mempool sync skips pre-v5 for the same reason.
fn wtxid_for_received_tx(
    pending_tx_responses: &mut RequestWindow<TxInventoryKey>,
    payload: &[u8],
) -> Option<WtxId> {
    let derived = wtxid_from_tx_bytes(payload, SOVRIGHT_P2P_CONSENSUS_BRANCH_ID)?;

    let wtx_match = pending_tx_responses.complete(TxInventoryKey::from_wtxid(&derived));
    // MSG_TX names only the txid. The payload-derived wtxid still supplies the
    // cache identity, but also satisfies a request made using that older form.
    let tx_match = pending_tx_responses.complete(TxInventoryKey::tx(*derived.txid().as_bytes()));
    if let Some(index) = wtx_match.or(tx_match) {
        if index != 0 {
            warn!(
                pending_index = index,
                "Received requested transaction out of order"
            );
        }
    } else {
        // Unsolicited, or the request already fell out of the queue. The
        // payload still identifies itself, so it is safe to cache -- and
        // dropping it would discard a transaction we may need.
        warn!("Received transaction matching no pending request");
    }

    Some(derived)
}

fn received_block_display_hash(
    pending_block_responses: &mut RequestWindow<[u8; 32]>,
    block_payload: &[u8],
) -> Result<String> {
    let actual_inventory_hash = raw_hash_from_header(block_payload)?;
    let actual_hash = inventory_hash_to_display(&actual_inventory_hash);
    if let Some(index) = pending_block_responses.complete(actual_inventory_hash) {
        if index != 0 {
            warn!(
                actual_hash,
                pending_index = index,
                "Received requested block out of order"
            );
        }
        return Ok(actual_hash);
    }

    if let Some((hash, _)) = pending_block_responses.pending.front() {
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

    fn request_window<K: Copy + Eq + Hash>(keys: impl IntoIterator<Item = K>) -> RequestWindow<K> {
        let mut window = RequestWindow::new(8, 16, Duration::from_secs(30));
        for key in keys {
            assert!(window.admit(key, Instant::now()));
        }
        window
    }

    // NU6.3/Ironwood (mainnet height 3,428,143, 2026-07-28) moved the network to
    // protocol 170_160. We advertised 170_150 through activation: peers completed
    // the handshake and then relayed NOTHING, so block ingest went to ~zero for
    // ~6h while every service still reported healthy. This test pins the
    // advertised version to the current upgrade so the same silent failure cannot
    // recur unnoticed -- when the next NU lands, this test is what fails first.
    #[test]
    fn advertised_protocol_version_matches_current_network_upgrade() {
        // Authoritative source: `getnetworkinfo.protocolversion` on an upgraded
        // zebrad (6.2.3 reports 170160). Do NOT infer this from peer counts.
        assert_eq!(PROTOCOL_VERSION, 170_160);
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
        let mut pending = request_window([]);
        let mut hash = [0u8; 32];
        hash[0] = 0x5c;
        hash[31] = 0x01;
        assert!(pending.admit(hash, Instant::now()));
        let block_payload = vec![0u8; sovright_relay::ZCASH_FULL_HEADER_SIZE];
        let expected = display_hash_from_header(&block_payload).unwrap();

        let display = received_block_display_hash(&mut pending, &block_payload).unwrap();

        assert_eq!(display, expected);
        assert_eq!(pending.pending.len(), 1);
        assert_eq!(pending.pending[0].0, hash);
    }

    #[test]
    fn received_block_display_removes_matching_out_of_order_pending_hash() {
        let mut pending = request_window([[0x5c; 32]]);

        let block_payload = vec![0u8; sovright_relay::ZCASH_FULL_HEADER_SIZE];
        let actual_display = display_hash_from_header(&block_payload).unwrap();
        let actual_inventory = inventory_hash_from_display(&actual_display);
        assert!(pending.admit(actual_inventory, Instant::now()));

        let display = received_block_display_hash(&mut pending, &block_payload).unwrap();

        assert_eq!(display, actual_display);
        assert_eq!(pending.pending.len(), 1);
        assert_eq!(pending.pending[0].0, [0x5c; 32]);
    }

    #[test]
    fn received_block_display_falls_back_to_payload_header_hash_without_pending_request() {
        let mut pending = request_window([]);
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
        let mut window = request_window([]);
        let mut requests = Vec::new();

        let queued = queue_tx_request(inv, true, 1, &mut window, &mut requests, Instant::now());

        let key = TxInventoryKey::wtx([0x11; 32], [0x22; 32]);
        assert_eq!(queued, Some(key));
        assert_eq!(window.pending.len(), 1);
        assert_eq!(window.pending[0].0, key);
        assert_eq!(requests, vec![inv]);
    }

    #[test]
    fn skips_transaction_inventory_when_cache_disabled_or_limit_reached() {
        let inv = Inventory {
            inv_type: MSG_TX,
            hash: [0x33; 32],
            auth_digest: None,
        };
        let mut window = request_window([]);
        let mut requests = Vec::new();

        assert_eq!(
            queue_tx_request(inv, false, 1, &mut window, &mut requests, Instant::now(),),
            None
        );
        assert_eq!(
            queue_tx_request(inv, true, 0, &mut window, &mut requests, Instant::now(),),
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

    /// A real NU6.3 v6 mainnet transaction, so the wtxid is derived by the same
    /// ZIP-244/229 path production uses rather than a stand-in.
    const V6_TX_HEX: &str = include_str!("../tests/fixtures/mainnet_v6_tx.hex");

    fn v6_tx() -> Vec<u8> {
        hex::decode(V6_TX_HEX.trim()).expect("v6 fixture hex")
    }

    fn v6_wtxid() -> WtxId {
        wtxid_from_tx_bytes(&v6_tx(), SOVRIGHT_P2P_CONSENSUS_BRANCH_ID).expect("v6 resolves")
    }

    /// THE regression. A peer answered an earlier request out of order (or
    /// never answered it), so the front of the queue is some other
    /// transaction. Keying by the queue cached this payload under THAT wtxid --
    /// which is how ~74% of compact reconstructions ended up assembling the
    /// wrong transactions while every short_id resolved cleanly.
    #[test]
    fn a_tx_is_keyed_by_its_own_payload_not_the_front_of_the_queue() {
        let other = TxInventoryKey::tx([0x77; 32]);
        let mut pending = request_window([other, TxInventoryKey::from_wtxid(&v6_wtxid())]);

        let keyed = wtxid_for_received_tx(&mut pending, &v6_tx()).expect("v6 keys");

        assert_eq!(keyed, v6_wtxid(), "payload must decide the key");
        assert_ne!(
            keyed,
            other.to_wtxid(),
            "the queue front must not decide it"
        );
    }

    /// The out-of-order response must consume ITS OWN queue entry, leaving the
    /// still-outstanding request in place. Popping the front instead is what
    /// desynchronised the queue permanently.
    #[test]
    fn an_out_of_order_tx_removes_its_own_pending_entry() {
        let still_outstanding = TxInventoryKey::tx([0x77; 32]);
        let mut pending =
            request_window([still_outstanding, TxInventoryKey::from_wtxid(&v6_wtxid())]);

        wtxid_for_received_tx(&mut pending, &v6_tx()).expect("v6 keys");

        assert_eq!(
            pending
                .pending
                .iter()
                .map(|(key, _)| *key)
                .collect::<Vec<_>>(),
            vec![still_outstanding],
            "only the matching request should be consumed"
        );
    }

    /// A peer that silently omits one transaction used to shift every
    /// subsequent payload onto the wrong key forever. Now the omission simply
    /// leaves its request outstanding and the next payload is keyed correctly.
    #[test]
    fn a_skipped_response_does_not_desynchronise_later_ones() {
        let never_answered = TxInventoryKey::tx([0x99; 32]);
        let mut pending = request_window([never_answered, TxInventoryKey::from_wtxid(&v6_wtxid())]);

        let keyed = wtxid_for_received_tx(&mut pending, &v6_tx()).expect("v6 keys");

        assert_eq!(keyed, v6_wtxid());
        assert_eq!(
            pending.pending.len(),
            1,
            "the unanswered request stays outstanding"
        );
    }

    /// Pre-v5 has no auth digest, so no wtxid can be derived. Caching it under
    /// the queue's guess is precisely the bug; a cache miss costs one
    /// getblocktxn round trip, a wrong key costs a whole block.
    #[test]
    fn a_pre_v5_payload_is_not_cached_under_a_guess() {
        let mut pending = request_window([TxInventoryKey::tx([0x77; 32])]);
        // v4 transaction prefix: parses, but carries no auth digest.
        let v4 = vec![0x04, 0x00, 0x00, 0x80, 0x01, 0x02, 0x03];
        assert!(wtxid_for_received_tx(&mut pending, &v4).is_none());
        assert_eq!(pending.pending.len(), 1, "the request stays outstanding");
    }

    #[test]
    fn a_malformed_payload_is_not_cached_under_a_guess() {
        let mut pending = request_window([TxInventoryKey::tx([0x77; 32])]);
        assert!(wtxid_for_received_tx(&mut pending, &[0xff, 0xff, 0xff]).is_none());
        assert_eq!(pending.pending.len(), 1);
    }

    /// An unsolicited transaction still identifies itself, so it is cached
    /// rather than discarded -- we may need it, and its key cannot be wrong.
    #[test]
    fn an_unsolicited_tx_is_still_keyed_by_its_payload() {
        let mut pending = request_window([]);
        let keyed = wtxid_for_received_tx(&mut pending, &v6_tx()).expect("v6 keys");
        assert_eq!(keyed, v6_wtxid());
    }

    fn peer_test_config() -> Config {
        Config {
            seeds: Vec::new(),
            peers: Vec::new(),
            max_peers: 1,
            connect_timeout: Duration::from_secs(5),
            peer_runtime: Duration::ZERO,
            crawler_enabled: false,
            crawler_max_known_peers: 1,
            crawler_max_addr_per_message: 1,
            crawler_drain_interval: Duration::from_secs(1),
            rotation_enabled: false,
            rotation_cooldown: Duration::ZERO,
            rotation_failure_cooldown: Duration::ZERO,
            accept_nonstandard_ports: true,
            excluded_peer_ips: HashSet::new(),
            peer_scoring_enabled: false,
            peer_score_block_inv: 5,
            peer_score_block_first: 100,
            peer_score_block_second: 50,
            peer_score_block_third: 25,
            peer_score_half_life: Duration::from_secs(3600),
            peer_score_block_received: 25,
            peer_score_relay_forwarded: 10,
            peer_score_error: -50,
            tx_cache_enabled: true,
            tx_cache_max_entries: 8,
            tx_cache_max_bytes: 4096,
            tx_cache_max_tx_bytes: 4096,
            tx_feed_addr: None,
            tx_request_limit_per_inv: 256,
            inventory_limits: Default::default(),
            event_log: None,
            relay_peers: Vec::new(),
            relay_bind_addr: "127.0.0.1:0".parse().unwrap(),
            relay_auth_key: None,
            relay_data_shards: 10,
            relay_parity_shards: 3,
            relay_adaptive_fec: false,
            relay_send_burst_packets: 0,
            relay_send_burst_delay_micros: 0,
            relay_compact_from_tx_cache: false,
            relay_skeleton_first: false,
            relay_raw_fallback_with_tx_cache: false,
            relay_raw_segment_send_rounds: 1,
            relay_raw_segment_round_delay_millis: 0,
            relay_forward_dedup_window: Duration::from_secs(30),
            relay_forward_dedup_capacity: 64,
            submitblock_rpc: None,
        }
    }

    struct TestPeer {
        stream: TcpStream,
        task: tokio::task::JoinHandle<Result<()>>,
        log: std::path::PathBuf,
    }

    impl Drop for TestPeer {
        fn drop(&mut self) {
            self.task.abort();
            let _ = fs::remove_file(&self.log);
        }
    }

    impl TestPeer {
        async fn start(name: &str, config: Config) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let log = temp_log_path(name);
            let events = EventSink::new(Some(log.clone())).unwrap();
            let crawler = Crawler::new(&config, [address]);
            let cache = TxCache::new(crate::tx_cache::TxCacheConfig {
                max_entries: 8,
                max_bytes: 4096,
                max_tx_bytes: 4096,
            });
            let task = tokio::spawn(run_peer(
                address,
                config,
                events,
                None,
                Some(cache),
                None,
                crawler,
            ));
            let (mut stream, _) = timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            stream.set_nodelay(true).unwrap();
            assert_eq!(read_message(&mut stream).await.unwrap().command, "version");
            write_message(&mut stream, "version", &version_payload(address))
                .await
                .unwrap();
            write_message(&mut stream, "verack", &[]).await.unwrap();
            let mut peer = Self { stream, task, log };
            assert!(peer.barrier().await.is_empty());
            peer
        }

        // The pong is ordered after processing all preceding messages, so a
        // missing getdata is observable without a timing-dependent sleep.
        async fn barrier(&mut self) -> Vec<Inventory> {
            write_message(&mut self.stream, "ping", &42u64.to_le_bytes())
                .await
                .unwrap();
            timeout(Duration::from_secs(5), async {
                let mut requests = Vec::new();
                loop {
                    let message = read_message(&mut self.stream).await.unwrap();
                    match message.command.as_str() {
                        "getdata" => requests.extend(parse_inventory(&message.payload).unwrap()),
                        "pong" => return requests,
                        _ => {}
                    }
                }
            })
            .await
            .unwrap()
        }

        async fn announce(&mut self, items: &[Inventory]) -> Vec<Inventory> {
            write_message(&mut self.stream, "inv", &encode_inventory(items))
                .await
                .unwrap();
            self.barrier().await
        }
    }

    fn numbered_inventory(inv_type: u32, number: u64) -> Inventory {
        let mut hash = [0; 32];
        hash[..8].copy_from_slice(&number.to_le_bytes());
        Inventory {
            inv_type,
            hash,
            auth_digest: (inv_type == MSG_WTX).then_some([0x42; 32]),
        }
    }

    #[tokio::test]
    async fn fresh_block_inventory_without_responses_has_a_per_peer_bound() {
        let mut peer = TestPeer::start("block-flood", peer_test_config()).await;
        let mut requested = 0;
        for batch in 0..8 {
            let invs: Vec<_> = (0..256)
                .map(|n| numbered_inventory(crate::wire::MSG_BLOCK, batch * 256 + n))
                .collect();
            requested += peer.announce(&invs).await.len();
            assert!(
                requested <= 128,
                "unanswered block requests grew to {requested}"
            );
        }
        assert_eq!(requested, 128);
    }

    #[tokio::test]
    async fn fresh_transaction_inventory_without_responses_has_a_per_peer_bound() {
        let mut peer = TestPeer::start("tx-flood", peer_test_config()).await;
        let mut requested = 0;
        for batch in 0..8 {
            let invs: Vec<_> = (0..256)
                .map(|n| numbered_inventory(MSG_WTX, batch * 256 + n))
                .collect();
            requested += peer.announce(&invs).await.len();
            assert!(
                requested <= 1024,
                "unanswered tx requests grew to {requested}"
            );
        }
        assert_eq!(requested, 1024);
    }

    #[tokio::test]
    async fn notfound_releases_block_and_transaction_requests_for_retry() {
        let mut peer = TestPeer::start("notfound", peer_test_config()).await;
        let invs = [
            numbered_inventory(crate::wire::MSG_BLOCK, 1),
            numbered_inventory(MSG_WTX, 2),
        ];
        assert_eq!(peer.announce(&invs).await, invs);
        assert!(
            peer.announce(&invs).await.is_empty(),
            "duplicates must not request twice"
        );
        write_message(&mut peer.stream, "notfound", &encode_inventory(&invs))
            .await
            .unwrap();
        assert_eq!(
            peer.announce(&invs).await,
            invs,
            "notfound must release all correlated request state"
        );
    }

    #[test]
    fn floods_do_not_retain_rejected_inventory_or_grow_recent_caches() {
        // Exercise the same window for both block hashes and transaction keys.
        fn check<K: Copy + Eq + Hash>(key: impl Fn(u64) -> K) {
            let now = Instant::now();
            let mut window = RequestWindow::new(2, 3, Duration::from_secs(30));
            let mut announcements = RecentInventory::new(3);
            for n in 0..10_000 {
                announcements.insert(key(n));
                assert_eq!(window.admit(key(n), now), n < 2);
                assert!(window.pending.len() <= 2);
                assert!(announcements.keys.len() <= 3);
                assert!(announcements.order.len() <= 3);
            }
            assert!(
                window.recent.keys.is_empty(),
                "rejected requests leave no history"
            );
            assert!(window.recent.order.is_empty());
            assert_eq!(window.remove(key(0)), Some(0));
            assert_eq!(window.remove(key(1)), Some(0));
            for n in 0..10_000 {
                assert!(window.admit(key(n), now));
                assert_eq!(window.complete(key(n)), Some(0));
                assert!(
                    !window.admit(key(n), now),
                    "completed duplicates stay suppressed"
                );
                assert!(window.recent.keys.len() <= 3);
                assert!(window.recent.order.len() <= 3);
            }
            assert!(
                window.admit(key(0), now),
                "old completed history is evicted"
            );
        }
        check(|n| numbered_inventory(crate::wire::MSG_BLOCK, n).hash);
        check(|n| TxInventoryKey::from_inventory(&numbered_inventory(MSG_WTX, n)).unwrap());
    }

    #[test]
    fn duplicate_inventory_does_not_extend_deadlines_or_consume_capacity() {
        let now = Instant::now();
        let mut window = RequestWindow::new(2, 1, Duration::from_secs(30));
        assert!(window.admit(1, now));
        for _ in 0..10_000 {
            assert!(!window.admit(1, now + Duration::from_secs(29)));
        }
        assert!(window.admit(2, now + Duration::from_secs(1)));
        window.expire(now + Duration::from_secs(29));
        assert_eq!(window.pending.len(), 2);
        window.expire(now + Duration::from_secs(30));
        assert_eq!(window.pending.len(), 1);
        assert_eq!(window.pending[0].0, 2);
        assert!(window.admit(1, now + Duration::from_secs(30)));
        assert!(!window.admit(3, now + Duration::from_secs(30)));
        window.expire(now + Duration::from_secs(31));
        assert!(window.admit(3, now + Duration::from_secs(31)));
    }

    #[test]
    fn zero_request_and_recent_limits_do_not_retain_state() {
        let now = Instant::now();
        let mut disabled = RequestWindow::new(0, 0, Duration::from_secs(30));
        assert!(!disabled.admit(1, now));
        assert!(disabled.pending.is_empty());
        let mut uncached = RequestWindow::new(1, 0, Duration::from_secs(30));
        assert!(uncached.admit(1, now));
        uncached.complete(1);
        assert!(uncached.recent.keys.is_empty());
        assert!(uncached.recent.order.is_empty());
        assert!(uncached.admit(1, now));
    }

    #[test]
    fn tx_response_releases_both_inventory_forms_without_guessing_identity() {
        let derived = v6_wtxid();
        let tx = TxInventoryKey::tx(*derived.txid().as_bytes());
        let wtx = TxInventoryKey::from_wtxid(&derived);
        let unrelated = TxInventoryKey::tx([0x88; 32]);
        let mut window = request_window([unrelated, tx, wtx]);
        assert_eq!(wtxid_for_received_tx(&mut window, &v6_tx()), Some(derived));
        assert_eq!(window.pending.len(), 1);
        assert_eq!(window.pending[0].0, unrelated);
        assert!(!window.admit(tx, Instant::now()));
        assert!(!window.admit(wtx, Instant::now()));
    }

    #[tokio::test]
    async fn responses_and_notfound_release_only_matching_slots() {
        let mut config = peer_test_config();
        config.inventory_limits.blocks = 2;
        config.inventory_limits.transactions = 2;
        let mut peer = TestPeer::start("matching-slots", config).await;
        let payload = vec![0; sovright_relay::ZCASH_FULL_HEADER_SIZE];
        let block = Inventory {
            inv_type: crate::wire::MSG_BLOCK,
            hash: raw_hash_from_header(&payload).unwrap(),
            auth_digest: None,
        };
        let tx = TxInventoryKey::from_wtxid(&v6_wtxid()).to_inventory();
        let unanswered = [
            numbered_inventory(crate::wire::MSG_BLOCK, 7),
            numbered_inventory(MSG_WTX, 8),
        ];
        let answered = [block, tx];
        assert_eq!(peer.announce(&unanswered).await, unanswered);
        assert_eq!(peer.announce(&answered).await, answered);
        let fresh = [
            numbered_inventory(crate::wire::MSG_BLOCK, 9),
            numbered_inventory(MSG_WTX, 10),
        ];
        assert!(peer.announce(&fresh).await.is_empty());
        write_message(&mut peer.stream, "notfound", &encode_inventory(&fresh))
            .await
            .unwrap();
        assert!(
            peer.announce(&fresh).await.is_empty(),
            "unsolicited notfound must not free a slot"
        );
        write_message(&mut peer.stream, "block", &payload)
            .await
            .unwrap();
        write_message(&mut peer.stream, "tx", &v6_tx())
            .await
            .unwrap();
        assert_eq!(
            peer.announce(&fresh).await,
            fresh,
            "out-of-order responses must free their own slots"
        );
        assert!(peer.announce(&unanswered).await.is_empty());
        write_message(&mut peer.stream, "notfound", &encode_inventory(&fresh))
            .await
            .unwrap();
        assert!(
            peer.announce(&answered).await.is_empty(),
            "recently completed responses stay deduplicated"
        );
        assert_eq!(peer.announce(&fresh).await, fresh);
    }

    #[tokio::test]
    async fn expiry_during_partial_frame_keeps_decoder_and_both_request_windows_usable() {
        use tokio::io::AsyncWriteExt;
        let mut config = peer_test_config();
        config.inventory_limits.blocks = 1;
        config.inventory_limits.transactions = 1;
        config.inventory_limits.timeout = Duration::from_millis(50);
        let mut peer = TestPeer::start("partial-expiry", config).await;
        let invs = [
            numbered_inventory(crate::wire::MSG_BLOCK, 1),
            numbered_inventory(MSG_WTX, 2),
        ];
        assert_eq!(peer.announce(&invs).await, invs);
        let mut frame = Vec::new();
        write_message(&mut frame, "inv", &encode_inventory(&invs))
            .await
            .unwrap();
        peer.stream.write_all(&frame[..25]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        peer.stream.write_all(&frame[25..]).await.unwrap();
        assert_eq!(
            peer.barrier().await,
            invs,
            "expiry must release both requests without cancelling a partial read"
        );
    }

    #[tokio::test]
    async fn disconnect_discards_request_state_before_a_new_connection() {
        use tokio::io::AsyncWriteExt;
        let config = peer_test_config();
        let invs = [
            numbered_inventory(crate::wire::MSG_BLOCK, 1),
            numbered_inventory(MSG_WTX, 2),
        ];
        let mut first = TestPeer::start("disconnect-first", config.clone()).await;
        assert_eq!(first.announce(&invs).await, invs);
        first.stream.shutdown().await.unwrap();
        assert!(
            timeout(Duration::from_secs(5), &mut first.task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        let mut second = TestPeer::start("disconnect-second", config).await;
        assert_eq!(second.announce(&invs).await, invs);
    }

    #[tokio::test]
    async fn full_request_window_preserves_announcement_scoring() {
        let mut config = peer_test_config();
        config.inventory_limits.blocks = 1;
        config.peer_scoring_enabled = true;
        let mut peer = TestPeer::start("score-full-window", config).await;
        let invs = [
            numbered_inventory(crate::wire::MSG_BLOCK, 1),
            numbered_inventory(crate::wire::MSG_BLOCK, 2),
        ];
        assert_eq!(peer.announce(&invs).await, invs[..1]);
        assert!(peer.announce(&invs).await.is_empty());
        let rows: Vec<serde_json::Value> = fs::read_to_string(&peer.log)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let scores: Vec<_> = rows
            .iter()
            .filter(|row| row["event"] == "p2p_peer_score")
            .collect();
        assert_eq!(
            scores.len(),
            2,
            "both announcements earn their rank award, duplicates earn none"
        );
        assert_eq!(scores[0]["score"], 100);
        assert_eq!(scores[1]["score"], 200);
    }
}
