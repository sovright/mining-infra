use std::collections::{HashSet, VecDeque};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::coinbase::coinbase_telemetry_off_workers;
use crate::config::Config;
use crate::crawler::Crawler;
use crate::error::{IngressError, Result};
use crate::event::EventSink;
use crate::hash::{inventory_hash_to_display, raw_hash_from_header};
use crate::relay_bridge::{ForwardMode, ForwardedBlock, RelayBridge};
use crate::tx_cache::{TxCache, TxInventoryKey};
use crate::tx_feed::TxFeedClient;
use crate::wire::{
    Inventory, encode_compact_size, encode_inventory, parse_addr, parse_inventory, read_i32_le,
    read_message, write_message,
};
use crate::wire::{MIN_ACCEPTABLE_REMOTE_VERSION, Network};
use crate::wtxid::{TX_READER_BRANCH_HINT, wtxid_from_tx_bytes};
use sovright_relay::{BlockBodyError, WtxId};

// Advertising less than we demand of peers would be incoherent; enforce at
// compile time so a future upgrade cannot raise the floor past what we send.
const _: () = assert!(Network::Mainnet.protocol_version() >= MIN_ACCEPTABLE_REMOTE_VERSION);
const _: () = assert!(Network::Testnet.protocol_version() >= MIN_ACCEPTABLE_REMOTE_VERSION);

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
    let relay = relay.map(|relay| relay.logging_block_events(events.clone(), &peer));
    // This is a capability filter, not consensus validation. Apply it for the
    // whole connection lifetime, before/at/after activation and across reorgs.
    // Peer-reported heights never control admission; only configuration does.
    let minimum_version = if relay.is_some() || tx_feed.is_some() {
        config.forwarding_min_peer_version()
    } else {
        MIN_ACCEPTABLE_REMOTE_VERSION
    };
    let connect_started = Instant::now();
    let stream = timeout(config.connect_timeout, TcpStream::connect(peer_addr))
        .await
        .map_err(|_| IngressError::Timeout(format!("connect to {peer}")))??;
    events.p2p_connect_timing(&peer, connect_started.elapsed().as_millis())?;
    stream.set_nodelay(true)?;
    events.p2p_peer_connected(&peer)?;
    info!(%peer, "connected to Zcash P2P peer");

    let (mut reader, mut writer) = stream.into_split();
    let version = version_payload(peer_addr, config.network);
    write_message(&mut writer, config.network, "version", &version).await?;

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
        let read = timeout(
            Duration::from_secs(90),
            read_message(&mut reader, config.network),
        );
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

        if (!sent_verack || !saw_verack) && !matches!(msg.command.as_str(), "version" | "verack") {
            if msg.command == "reject" {
                events.p2p_reject(&peer, msg.payload.len())?;
            }
            return Err(IngressError::Wire(format!(
                "{} received before handshake completion",
                msg.command
            )));
        }
        match msg.command.as_str() {
            "version" => {
                if sent_verack {
                    return Err(IngressError::Wire("duplicate version message".to_string()));
                }
                let remote_version = remote_version(&msg.payload).unwrap_or_default();
                info!(%peer, remote_version, "received version");
                events.p2p_peer_version(&peer, remote_version)?;
                if remote_version < minimum_version {
                    return Err(IngressError::Wire(format!(
                        "remote protocol version too old: {remote_version} < {minimum_version}"
                    )));
                }
                if !sent_verack {
                    write_message(&mut writer, config.network, "verack", &[]).await?;
                    sent_verack = true;
                }
            }
            "verack" => {
                if !sent_verack {
                    return Err(IngressError::Wire(
                        "verack received before version admission".to_string(),
                    ));
                }
                if saw_verack {
                    return Err(IngressError::Wire("duplicate verack message".to_string()));
                }
                saw_verack = true;
                events.p2p_handshake_complete(&peer)?;
                events.p2p_handshake_timing(&peer, handshake_started.elapsed().as_millis())?;
                let nonce = nonce();
                write_message(&mut writer, config.network, "ping", &nonce.to_le_bytes()).await?;
                ping_nonce = Some(nonce);
                ping_started = Some(Instant::now());
                write_message(&mut writer, config.network, "getaddr", &[]).await?;
            }
            "reject" => {
                events.p2p_reject(&peer, msg.payload.len())?;
            }
            "addr" => {
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
                write_message(&mut writer, config.network, "pong", &msg.payload).await?;
            }
            "inv" => {
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
                    write_message(&mut writer, config.network, "getdata", &request).await?;
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
                    write_message(&mut writer, config.network, "getdata", &request).await?;
                    for key in requested_keys {
                        events.p2p_tx_getdata_sent(&peer, key.kind(), &key.display_hash())?;
                    }
                }
            }
            "notfound" => {
                for inv in parse_inventory(&msg.payload)? {
                    if inv.is_block() {
                        blocks.remove(inv.hash);
                    } else if let Some(key) = TxInventoryKey::from_inventory(&inv) {
                        transactions.remove(key);
                    }
                }
            }
            "block" => {
                let display = received_block_display_hash(&mut blocks, &msg.payload)?;
                let consensus_hash = msg
                    .payload
                    .get(..sovright_relay::ZCASH_FULL_HEADER_SIZE)
                    .map(sovright_relay::consensus_block_hash_display)
                    .unwrap_or_default();
                // Nothing here needs parsing, so the receipt is on record before
                // anything can wait, and survives whatever happens to the forward.
                events.p2p_block_received(&peer, &display, &consensus_hash, msg.payload.len())?;
                if let Some(relay) = &relay {
                    let outcome = relay.forward_block(&msg.payload, tx_cache.as_ref()).await;
                    match &outcome {
                        Ok(forwarded) => {
                            events.p2p_relay_block_forwarded(
                                &peer,
                                &display,
                                forwarded.bytes,
                                forwarded.tx_count,
                                forwarded.mode.as_str(),
                                forwarded.relay_objects,
                            )?;
                        }
                        Err(error) => {
                            if let IngressError::InvalidBlockBody(rejection) = error {
                                events.p2p_block_body_rejected(
                                    &peer,
                                    &display,
                                    &consensus_hash,
                                    rejection,
                                    msg.payload.len(),
                                )?;
                            }
                            events
                                .p2p_peer_error(&peer, &format!("relay forward failed: {error}"))?;
                        }
                    }
                    for (delta, reason) in delivery_scores(&config, &outcome) {
                        crawler.score_peer(peer_addr, delta, reason, &events)?;
                    }
                } else {
                    let coinbase = coinbase_telemetry_off_workers(&msg.payload).await;
                    events.p2p_block_coinbase_unverified(
                        &peer,
                        &display,
                        &consensus_hash,
                        &coinbase,
                    )?;
                    crawler.score_peer(
                        peer_addr,
                        config.peer_score_block_received,
                        "block_received",
                        &events,
                    )?;
                }
            }
            "tx" => {
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

/// What a delivery earns once the relay has judged it. Only a block validated and
/// sent on is rewarded: a deduplicated copy was not parsed and an unverified one
/// could not be, so neither says anything about the peer, and a relay failure is
/// not the peer's doing.
fn delivery_scores(config: &Config, outcome: &Result<ForwardedBlock>) -> Vec<(i64, &'static str)> {
    match outcome {
        Ok(forwarded)
            if matches!(
                forwarded.mode,
                ForwardMode::Deduplicated | ForwardMode::RawBlockSegmentsUnverified
            ) =>
        {
            Vec::new()
        }
        Ok(_) => vec![
            (config.peer_score_block_received, "block_received"),
            (config.peer_score_relay_forwarded, "relay_forwarded"),
        ],
        Err(IngressError::InvalidBlockBody(error)) if !may_be_a_reader_gap(error) => {
            vec![(config.peer_score_error, "invalid_block_body")]
        }
        Err(_) => Vec::new(),
    }
}

/// A valid block in a layout this reader does not know fails with one of these.
/// Every honest peer delivers that block, so they cannot be held against a peer.
fn may_be_a_reader_gap(error: &BlockBodyError) -> bool {
    matches!(
        error,
        BlockBodyError::Transaction { .. } | BlockBodyError::TrailingBytes { .. }
    )
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
    let derived = wtxid_from_tx_bytes(payload, TX_READER_BRANCH_HINT)?;

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

fn version_payload(peer_addr: SocketAddr, network: Network) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&network.protocol_version().to_le_bytes());
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
    use crate::relay_bridge::POOL_GATEWAY_SOURCE;
    use crate::relay_bridge::block_body_tests::{
        Harness, bypass_harness, checked_harness, compact_blocks_of, eventually, fill_send_channel,
        good_and_bad, harness, hash_of, header_missing_its_target, hold_p2p_permit, in_flight,
        unreadable_block, unreadable_body,
    };
    use crate::tx_cache::TxInventoryKey;
    use crate::wire::{MSG_TX, MSG_WTX};
    use std::fs;

    fn temp_log_path(name: &str) -> std::path::PathBuf {
        // Tests run in parallel and several share a name, so pid and time alone
        // collide and one test's cleanup can delete another's log mid-read.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = format!(
            "sovright-p2p-peer-{name}-{}-{}-{}.jsonl",
            std::process::id(),
            unix_time_secs(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
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

    // Test serialized capability, not just a private constant: NU7 peers use
    // the first i32 of the version payload to decide whether to disconnect us.
    #[test]
    fn outgoing_version_satisfies_nu7_mainnet_peer_floor() {
        let payload = version_payload("127.0.0.1:8233".parse().unwrap(), Network::Mainnet);
        let advertised = i32::from_le_bytes(payload[..4].try_into().unwrap());
        assert_eq!(advertised, 170_190);
        assert_eq!(
            &payload[4..12],
            &[0; 8],
            "ingress must not claim full-node services"
        );
    }

    #[test]
    fn testnet_advertises_its_own_version_with_unchanged_services() {
        let payload = version_payload("127.0.0.1:18233".parse().unwrap(), Network::Testnet);
        assert_eq!(i32::from_le_bytes(payload[..4].try_into().unwrap()), 170180);
        assert_eq!(u64::from_le_bytes(payload[4..12].try_into().unwrap()), 0);
    }

    #[test]
    fn version_payload_contains_user_agent() {
        let payload = version_payload("127.0.0.1:8233".parse().unwrap(), Network::Mainnet);
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
        wtxid_from_tx_bytes(&v6_tx(), TX_READER_BRANCH_HINT).expect("v6 resolves")
    }

    /// A real Sapling v4 transaction from mainnet block 3470793. It parses
    /// whole, so a `None` for it comes from the version check, not from a parse
    /// failure; `a_malformed_payload_is_not_cached_under_a_guess` covers that.
    fn v4_tx() -> Vec<u8> {
        zcash_pool_common::fixtures::mainnet_transactions()[3].clone()
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
        use zcash_primitives::transaction::{Transaction, TxVersion};
        let v4 = v4_tx();
        let mut cursor = std::io::Cursor::new(v4.as_slice());
        let parsed =
            Transaction::read(&mut cursor, TX_READER_BRANCH_HINT).expect("the v4 fixture parses");
        assert_eq!(cursor.position() as usize, v4.len(), "and is read whole");
        assert_eq!(parsed.version(), TxVersion::V4);

        // A request for this very transaction, as a peer announces a v4.
        let mut pending = request_window([TxInventoryKey::tx(*parsed.txid().as_ref())]);
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
            network: crate::wire::Network::Mainnet,
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
            metrics_textfile: None,
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
            relay_forward_unreadable_blocks: false,
            relay_unreadable_bodies_per_header: crate::config::DEFAULT_UNREADABLE_BODIES_PER_HEADER,
            relay_raw_segment_send_rounds: 1,
            relay_raw_wire: Default::default(),
            relay_bodies_per_header: 4,
            relay_raw_segment_round_delay_millis: 0,
            relay_forward_dedup_window: Duration::from_secs(30),
            relay_forward_dedup_capacity: 64,
            forwarding_min_peer_version: None,
            submitblock_rpc: None,
        }
    }

    struct TestPeer {
        network: Network,
        stream: TcpStream,
        task: tokio::task::JoinHandle<Result<()>>,
        log: std::path::PathBuf,
        cache: TxCache,
    }

    /// The tx cache bounds `TestPeer` uses unless a test picks its own.
    fn default_test_cache() -> crate::tx_cache::TxCacheConfig {
        crate::tx_cache::TxCacheConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_tx_bytes: 4096,
        }
    }

    impl Drop for TestPeer {
        fn drop(&mut self) {
            self.task.abort();
            let _ = fs::remove_file(&self.log);
        }
    }

    impl TestPeer {
        async fn start(name: &str, config: Config) -> Self {
            let version = config.network.protocol_version();
            Self::start_with_remote_version(name, config, version).await
        }

        async fn start_with_remote_version(
            name: &str,
            config: Config,
            remote_version: i32,
        ) -> Self {
            Self::start_inner(name, config, remote_version, default_test_cache(), None).await
        }

        async fn start_with_relay(name: &str, config: Config, relay: RelayBridge) -> Self {
            let version = config.network.protocol_version();
            Self::start_inner(name, config, version, default_test_cache(), Some(relay)).await
        }

        async fn start_with_cache(
            name: &str,
            config: Config,
            cache: crate::tx_cache::TxCacheConfig,
        ) -> Self {
            let version = config.network.protocol_version();
            Self::start_inner(name, config, version, cache, None).await
        }

        async fn start_inner(
            name: &str,
            config: Config,
            remote_version: i32,
            cache_config: crate::tx_cache::TxCacheConfig,
            relay: Option<RelayBridge>,
        ) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let log = temp_log_path(name);
            let network = config.network;
            let tx_feed = config.tx_feed_addr.map(TxFeedClient::new);
            let events = EventSink::for_network(Some(log.clone()), network).unwrap();
            let crawler = Crawler::new(&config, [address]);
            let cache = TxCache::new(cache_config);
            let task = tokio::spawn(run_peer(
                address,
                config,
                events,
                relay,
                Some(cache.clone()),
                tx_feed,
                crawler,
            ));
            let (mut stream, _) = timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            stream.set_nodelay(true).unwrap();
            assert_eq!(
                read_message(&mut stream, network).await.unwrap().command,
                "version"
            );
            let mut remote_payload = version_payload(address, network);
            remote_payload[..4].copy_from_slice(&remote_version.to_le_bytes());
            write_message(&mut stream, network, "version", &remote_payload)
                .await
                .unwrap();
            write_message(&mut stream, network, "verack", &[])
                .await
                .unwrap();
            let mut peer = Self {
                network,
                stream,
                task,
                log,
                cache,
            };
            assert!(peer.barrier().await.is_empty());
            peer
        }

        // The pong is ordered after processing all preceding messages, so a
        // missing getdata is observable without a timing-dependent sleep.
        async fn barrier(&mut self) -> Vec<Inventory> {
            let network = self.network;
            write_message(&mut self.stream, network, "ping", &42u64.to_le_bytes())
                .await
                .unwrap();
            timeout(Duration::from_secs(5), async {
                let mut requests = Vec::new();
                loop {
                    let message = read_message(&mut self.stream, network).await.unwrap();
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

        async fn send_block(&mut self, raw: &[u8]) {
            let network = self.network;
            write_message(&mut self.stream, network, "block", raw)
                .await
                .unwrap();
        }

        /// Deliver a block and wait until the peer task has finished with it.
        async fn deliver(&mut self, raw: &[u8]) {
            self.send_block(raw).await;
            self.barrier().await;
        }

        /// Cancel the peer task, as a rotation or a shutdown would.
        async fn cancel(&mut self) {
            self.task.abort();
            match (&mut self.task).await {
                Err(error) => assert!(error.is_cancelled()),
                Ok(_) => panic!("the peer task finished before it was cancelled"),
            }
        }

        fn events(&self, name: &str) -> Vec<serde_json::Value> {
            logged_events(&self.log)
                .into_iter()
                .filter(|event| event["event"] == name)
                .collect()
        }

        fn score_reasons(&self) -> Vec<String> {
            self.events("p2p_peer_score")
                .iter()
                .map(|event| event["reason"].as_str().unwrap().to_owned())
                .collect()
        }

        async fn announce(&mut self, items: &[Inventory]) -> Vec<Inventory> {
            let network = self.network;
            write_message(&mut self.stream, network, "inv", &encode_inventory(items))
                .await
                .unwrap();
            self.barrier().await
        }
    }

    /// Every feed connection already made, read to EOF. Non-blocking accept, so
    /// an empty result means none was made, not that none arrived in time.
    fn accept_feed(listener: &std::net::TcpListener) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // Accepted sockets inherit O_NONBLOCK on macOS/BSD.
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut line = String::new();
                    std::io::Read::read_to_string(&mut stream, &mut line).unwrap();
                    lines.push(line);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return lines,
                Err(error) => panic!("feed accept failed: {error}"),
            }
        }
    }

    fn logged_events(log: &std::path::Path) -> Vec<serde_json::Value> {
        fs::read_to_string(log)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn scored_config() -> Config {
        let mut config = peer_test_config();
        config.peer_scoring_enabled = true;
        config
    }

    /// A body the reader refuses outright, where the header commits to the bytes.
    fn unparseable_block() -> Vec<u8> {
        use sovright_relay::test_support::{committed_header, parseable_transaction, raw_block};
        let txs = [parseable_transaction(1), vec![0xff; 40]];
        raw_block(&committed_header(0xcd, &txs), &txs)
    }

    #[tokio::test]
    async fn a_refused_body_is_logged_counted_and_costs_the_peer() {
        let (_, bad) = good_and_bad();
        let harness = harness();
        let relay = harness.bridge.clone();
        let mut peer = TestPeer::start_with_relay("body-refused", scored_config(), relay).await;

        peer.deliver(&bad).await;

        let rejected = peer.events("p2p_block_body_rejected");
        let [event] = rejected.as_slice() else {
            panic!("expected one rejection, got {rejected:?}");
        };
        assert_eq!(event["reason"], "merkle_mismatch");
        assert_eq!(event["detail"], "merkle root mismatch");
        assert_eq!(event["bytes"], bad.len());
        assert_eq!(
            event["hash"],
            display_hash_from_header(&bad).unwrap().as_str()
        );
        assert_eq!(
            event["consensus_hash"],
            sovright_relay::consensus_block_hash_display(
                &bad[..sovright_relay::ZCASH_FULL_HEADER_SIZE]
            )
        );
        assert_eq!(peer.events("p2p_peer_error").len(), 1);
        assert_eq!(peer.score_reasons(), ["invalid_block_body"]);
        assert_eq!(peer.events("p2p_peer_score")[0]["score"], -50);
    }

    /// Both can be a valid block this reader does not know, which every honest
    /// peer would deliver. They are logged and counted, and cost nobody anything.
    #[tokio::test]
    async fn a_body_the_reader_may_have_misread_costs_the_peer_nothing() {
        let (good, _) = good_and_bad();
        let mut with_trailing_byte = good;
        with_trailing_byte.push(0);
        let harness = harness();
        let relay = harness.bridge.clone();
        let mut peer = TestPeer::start_with_relay("reader-gap", scored_config(), relay).await;

        peer.deliver(&unparseable_block()).await;
        peer.deliver(&with_trailing_byte).await;

        let reasons: Vec<_> = peer
            .events("p2p_block_body_rejected")
            .iter()
            .map(|event| event["reason"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(reasons, ["transaction", "trailing_bytes"]);
        assert!(
            peer.score_reasons().is_empty(),
            "{:?}",
            peer.score_reasons()
        );
        let rejections = harness.bridge.block_body_rejections();
        assert_eq!(rejections.count("transaction"), 1);
        assert_eq!(rejections.count("trailing_bytes"), 1);
    }

    /// No valid block misses its own target, so this is never a reader gap.
    #[tokio::test]
    async fn a_header_missing_its_target_costs_the_peer() {
        let harness = checked_harness(Network::Mainnet);
        let relay = harness.bridge.clone();
        let mut peer = TestPeer::start_with_relay("bad-target", scored_config(), relay).await;

        peer.deliver(&unreadable_body(&header_missing_its_target()))
            .await;

        let rejected = peer.events("p2p_block_body_rejected");
        let [event] = rejected.as_slice() else {
            panic!("expected one rejection, got {rejected:?}");
        };
        assert_eq!(event["reason"], "header_target");
        assert_eq!(peer.score_reasons(), ["invalid_block_body"]);
        assert_eq!(
            harness.bridge.block_body_rejections().count("transaction"),
            0
        );
    }

    /// The exemption is left to bodies whose header passed the check.
    #[tokio::test]
    async fn a_reader_gap_behind_a_passing_header_stays_exempt() {
        let harness = checked_harness(Network::Mainnet);
        let relay = harness.bridge.clone();
        let mut peer = TestPeer::start_with_relay("gap-passing", scored_config(), relay).await;

        peer.deliver(&unreadable_body(
            &zcash_pool_common::fixtures::mainnet_serialized_header(),
        ))
        .await;

        assert_eq!(
            peer.events("p2p_block_body_rejected")[0]["reason"],
            "transaction"
        );
        assert!(
            peer.score_reasons().is_empty(),
            "{:?}",
            peer.score_reasons()
        );
    }

    /// Extra bytes do not buy the exemption for a body that misses its header.
    #[tokio::test]
    async fn a_wrong_body_with_trailing_bytes_costs_the_peer() {
        let (_, mut bad) = good_and_bad();
        bad.push(0);
        let harness = harness();
        let relay = harness.bridge.clone();
        let mut peer = TestPeer::start_with_relay("trailing-bad", scored_config(), relay).await;

        peer.deliver(&bad).await;

        assert_eq!(
            peer.events("p2p_block_body_rejected")[0]["reason"],
            "merkle_mismatch"
        );
        assert_eq!(peer.score_reasons(), ["invalid_block_body"]);
    }

    /// It says nothing about the peer, its coinbase was never read, and the log
    /// says plainly that no body check ran on it.
    #[tokio::test]
    async fn an_unverified_forward_is_logged_and_earns_nothing() {
        let raw = unreadable_block(400, 1);
        let harness = bypass_harness();
        let relay = harness.bridge.clone();
        let mut peer = TestPeer::start_with_relay("unverified", scored_config(), relay).await;

        peer.deliver(&raw).await;

        let events = peer.events("p2p_block_unverified_forwarded");
        let [event] = events.as_slice() else {
            panic!("expected one line, got {events:?}");
        };
        assert_eq!(event["reason"], "transaction");
        assert_eq!(
            event["checks_run"],
            serde_json::json!(["size", "header", "proof_of_work"])
        );
        assert_eq!(
            event["checks_skipped"],
            serde_json::json!(["merkle", "duplicate_txid"])
        );
        assert_eq!(event["bytes"], raw.len());
        assert_eq!(
            event["consensus_hash"],
            sovright_relay::consensus_block_hash_display(
                &raw[..sovright_relay::ZCASH_FULL_HEADER_SIZE]
            )
        );
        assert_eq!(
            peer.events("p2p_relay_block_forwarded")[0]["mode"],
            "raw_block_segments_unverified"
        );
        assert!(peer.events("p2p_block_coinbase").is_empty());
        assert!(peer.events("p2p_block_body_rejected").is_empty());
        assert!(
            peer.score_reasons().is_empty(),
            "{:?}",
            peer.score_reasons()
        );
    }

    /// The first delivery was validated and sent. The rest were not parsed, good
    /// or bad, so they earn and cost nothing, however they read.
    #[tokio::test]
    async fn only_a_validated_new_block_earns_the_delivery_rewards() {
        let (good, bad) = good_and_bad();
        let harness = harness();
        let relay = harness.bridge.clone();
        let mut peer = TestPeer::start_with_relay("rewards", scored_config(), relay).await;

        peer.deliver(&good).await;
        assert_eq!(
            peer.score_reasons(),
            ["block_received", "relay_forwarded"],
            "a validated new block"
        );

        peer.deliver(&good).await;
        peer.deliver(&bad).await;
        peer.deliver(&good[..good.len() - 1]).await;

        assert_eq!(peer.score_reasons().len(), 2, "{:?}", peer.score_reasons());
        let forwarded = peer.events("p2p_relay_block_forwarded");
        let modes: Vec<_> = forwarded.iter().map(|event| &event["mode"]).collect();
        assert_eq!(
            modes,
            [
                "compact_block",
                "deduplicated",
                "deduplicated",
                "deduplicated"
            ]
        );
        assert!(peer.events("p2p_block_body_rejected").is_empty());
    }

    #[tokio::test]
    async fn a_relay_failure_costs_the_peer_nothing() {
        use crate::relay_bridge::block_body_tests::Harness;
        let (good, _) = good_and_bad();
        let Harness {
            bridge, outgoing, ..
        } = harness();
        drop(outgoing);
        let mut peer = TestPeer::start_with_relay("relay-down", scored_config(), bridge).await;

        peer.deliver(&good).await;

        assert_eq!(peer.events("p2p_peer_error").len(), 1);
        assert!(peer.events("p2p_block_body_rejected").is_empty());
        assert!(
            peer.score_reasons().is_empty(),
            "{:?}",
            peer.score_reasons()
        );
    }

    fn unix_time_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn event_names(peer: &TestPeer, kept: &[&str]) -> Vec<String> {
        logged_events(&peer.log)
            .iter()
            .map(|event| event["event"].as_str().unwrap().to_owned())
            .filter(|name| kept.contains(&name.as_str()))
            .collect()
    }

    const BLOCK_EVENTS: [&str; 4] = [
        "p2p_block_received",
        "p2p_block_coinbase",
        "p2p_block_body_rejected",
        "p2p_relay_block_forwarded",
    ];

    /// One receipt per delivery, and one coinbase line for the block that was read:
    /// the enrichment has its own name, so counting receipts stays right.
    #[tokio::test]
    async fn every_delivery_is_one_receipt_and_only_a_validated_new_block_has_a_coinbase() {
        let (good, bad) = good_and_bad();
        let harness = harness();
        let relay = harness.bridge.clone();
        let mut peer = TestPeer::start_with_relay("coinbase", peer_test_config(), relay).await;

        peer.deliver(&bad).await;
        peer.deliver(&good).await;
        peer.deliver(&good).await;

        assert_eq!(
            event_names(&peer, &BLOCK_EVENTS),
            [
                "p2p_block_received",
                "p2p_block_body_rejected",
                "p2p_block_received",
                "p2p_block_coinbase",
                "p2p_relay_block_forwarded",
                "p2p_block_received",
                "p2p_relay_block_forwarded",
            ]
        );
        let received = peer.events("p2p_block_received");
        assert!(
            received
                .iter()
                .all(|event| event.get("miner_script").is_none())
        );
        let coinbase = peer.events("p2p_block_coinbase");
        assert!(coinbase[0]["miner_script"].is_string());
        assert_eq!(coinbase[0]["hash"], received[1]["hash"]);
        assert_eq!(coinbase[0]["consensus_hash"], received[1]["consensus_hash"]);
        assert_eq!(coinbase[0]["peer"], received[1]["peer"]);
    }

    /// The forward is held at its permit, so it cannot have finished. The receipt
    /// is already in the log, and its time is before the permit was released.
    #[tokio::test]
    async fn the_receipt_is_logged_while_the_forward_waits_for_a_permit() {
        let (good, _) = good_and_bad();
        let harness = harness();
        let relay = harness.bridge.clone();
        let mut peer = TestPeer::start_with_relay("receipt", peer_test_config(), relay).await;
        let permit = hold_p2p_permit(&harness.bridge).await;

        peer.send_block(&good).await;
        eventually(|| peer.events("p2p_block_received").len() == 1).await;

        assert!(peer.events("p2p_relay_block_forwarded").is_empty());
        let released_at = unix_time_ms();
        drop(permit);
        peer.barrier().await;

        let arrived = peer.events("p2p_block_received")[0]["observed_at_unix_ms"]
            .as_u64()
            .unwrap();
        let forwarded = peer.events("p2p_relay_block_forwarded")[0]["observed_at_unix_ms"]
            .as_u64()
            .unwrap();
        assert!(arrived <= released_at, "{arrived} > {released_at}");
        assert!(released_at <= forwarded, "{released_at} > {forwarded}");
    }

    #[tokio::test]
    async fn a_forward_cancelled_at_its_permit_leaves_the_receipt() {
        let (good, _) = good_and_bad();
        let hash = hash_of(&good);
        let harness = harness();
        let relay = harness.bridge.clone();
        let mut peer = TestPeer::start_with_relay("cancel-queue", peer_test_config(), relay).await;
        let permit = hold_p2p_permit(&harness.bridge).await;
        peer.send_block(&good).await;
        eventually(|| peer.events("p2p_block_received").len() == 1).await;

        peer.cancel().await;
        drop(permit);

        assert_eq!(peer.events("p2p_block_received").len(), 1);
        assert_eq!(peer.events("p2p_block_received")[0]["bytes"], good.len());
        assert!(peer.events("p2p_relay_block_forwarded").is_empty());
        assert!(!in_flight(&harness.bridge, &hash));
        assert!(
            peer.events("p2p_block_coinbase").is_empty(),
            "it was never parsed"
        );
    }

    /// Past validation, holding the claim, waiting to send: the latest a forward
    /// can be cancelled. The claim goes and the receipt stays.
    #[tokio::test]
    async fn a_forward_cancelled_during_its_send_leaves_the_receipt() {
        let (good, _) = good_and_bad();
        let hash = hash_of(&good);
        let mut harness = harness();
        fill_send_channel(&harness.bridge).await;
        let relay = harness.bridge.clone();
        let mut peer = TestPeer::start_with_relay("cancel-send", peer_test_config(), relay).await;
        peer.send_block(&good).await;
        eventually(|| in_flight(&harness.bridge, &hash)).await;
        assert_eq!(peer.events("p2p_block_received").len(), 1);

        peer.cancel().await;

        assert!(!in_flight(&harness.bridge, &hash));
        assert_eq!(peer.events("p2p_block_received").len(), 1);
        assert!(peer.events("p2p_relay_block_forwarded").is_empty());
        assert_eq!(compact_blocks_of(&harness.sent(), &good), 0);
        let cancelled = peer.events("p2p_block_coinbase");
        assert_eq!(cancelled.len(), 1, "validated, so its miner is known");

        // Nothing was recorded, so a later copy sends it and writes its own line.
        let relay = harness.bridge.clone();
        let mut retry = TestPeer::start_with_relay("cancel-retry", peer_test_config(), relay).await;
        retry.deliver(&good).await;
        let retried = retry.events("p2p_block_coinbase");
        assert_eq!(retried.len(), 1);
        assert_eq!(retried[0]["consensus_hash"], cancelled[0]["consensus_hash"]);
        assert_eq!(retried[0]["miner_script"], cancelled[0]["miner_script"]);
    }

    /// A second line is not a copy of the first. The scriptSig is outside a v5 txid,
    /// so both bodies match the header, and each tag speaks only for its own body.
    #[tokio::test]
    async fn one_consensus_hash_can_have_lines_with_different_tags() {
        use crate::coinbase::tests::v5_coinbase_with_script_sig;
        use sovright_relay::test_support::{committed_header, raw_block};
        let coinbase = |tag: &[u8]| v5_coinbase_with_script_sig(&[&[3, 1, 2, 3], tag].concat());
        let (tag_a, tag_b) = (coinbase(b"pool-a"), coinbase(b"pool-b"));
        let header = committed_header(0xcd, std::slice::from_ref(&tag_a));
        let first = raw_block(&header, &[tag_a]);
        let second = raw_block(&header, &[tag_b]);
        let hash = hash_of(&first);
        let mut harness = harness();
        fill_send_channel(&harness.bridge).await;
        let relay = harness.bridge.clone();
        let mut sender = TestPeer::start_with_relay("tag-first", peer_test_config(), relay).await;
        sender.send_block(&first).await;
        eventually(|| in_flight(&harness.bridge, &hash)).await;
        sender.cancel().await;
        harness.sent();

        let relay = harness.bridge.clone();
        let mut retry = TestPeer::start_with_relay("tag-second", peer_test_config(), relay).await;
        retry.deliver(&second).await;

        let (first_line, second_line) = (
            sender.events("p2p_block_coinbase"),
            retry.events("p2p_block_coinbase"),
        );
        assert_eq!(
            first_line[0]["consensus_hash"],
            second_line[0]["consensus_hash"]
        );
        assert_eq!(
            first_line[0]["miner_script"],
            second_line[0]["miner_script"]
        );
        assert_eq!(first_line[0]["miner_tag"], "pool-a");
        assert_eq!(second_line[0]["miner_tag"], "pool-b");
    }

    #[tokio::test]
    async fn a_failed_send_keeps_the_coinbase() {
        let (good, _) = good_and_bad();
        let Harness {
            bridge, outgoing, ..
        } = harness();
        drop(outgoing);
        let mut peer = TestPeer::start_with_relay("send-failure", peer_test_config(), bridge).await;

        peer.deliver(&good).await;

        assert_eq!(
            event_names(&peer, &BLOCK_EVENTS),
            ["p2p_block_received", "p2p_block_coinbase"]
        );
        assert!(peer.events("p2p_block_coinbase")[0]["miner_script"].is_string());
    }

    /// The gateway forwards first, so the P2P copy is deduplicated and never
    /// parsed. Its receipt joins the gateway's line on the chain's hash.
    #[tokio::test]
    async fn a_gateway_block_is_attributed_by_the_gateway() {
        let (good, _) = good_and_bad();
        let harness = harness();
        let relay = harness.bridge.clone();
        let mut peer =
            TestPeer::start_with_relay("gateway-copy", peer_test_config(), relay.clone()).await;
        let events = EventSink::for_network(Some(peer.log.clone()), Network::Mainnet).unwrap();
        let gateway = relay.logging_block_events(events, POOL_GATEWAY_SOURCE);

        gateway.forward_pool_block(&good, None).await.unwrap();
        peer.deliver(&good).await;

        let coinbase = peer.events("p2p_block_coinbase");
        let [line] = coinbase.as_slice() else {
            panic!("expected one coinbase line, got {coinbase:?}");
        };
        assert_eq!(line["peer"], POOL_GATEWAY_SOURCE);
        assert!(line["miner_script"].is_string());
        let received = peer.events("p2p_block_received");
        assert_eq!(received[0]["consensus_hash"], line["consensus_hash"]);
        assert_eq!(
            line["consensus_hash"],
            sovright_relay::consensus_block_hash_display(
                &good[..sovright_relay::ZCASH_FULL_HEADER_SIZE]
            )
        );
        assert_eq!(
            peer.events("p2p_relay_block_forwarded")[0]["mode"],
            "deduplicated"
        );
    }

    /// A coinbase with no transparent bundle has nothing to report. That writes no
    /// enrichment line and does not touch the forward.
    #[tokio::test]
    async fn a_coinbase_with_nothing_to_report_does_not_stop_the_forward() {
        use sovright_relay::test_support::{committed_header, parseable_transaction, raw_block};
        let txs = [parseable_transaction(1)];
        let raw = raw_block(&committed_header(0xcd, &txs), &txs);
        let harness = harness();
        let relay = harness.bridge.clone();
        let mut peer = TestPeer::start_with_relay("no-coinbase", peer_test_config(), relay).await;

        peer.deliver(&raw).await;

        assert_eq!(
            event_names(&peer, &BLOCK_EVENTS),
            ["p2p_block_received", "p2p_relay_block_forwarded"]
        );
        let forwarded = peer.events("p2p_relay_block_forwarded");
        assert_eq!(forwarded[0]["mode"], "compact_block");
    }

    #[tokio::test]
    async fn without_a_relay_coinbase_observations_are_not_reported_as_validated() {
        let (good, bad) = good_and_bad();
        let mut peer = TestPeer::start("observe-coinbase", peer_test_config()).await;

        peer.deliver(&good).await;
        peer.deliver(&bad).await;

        assert!(peer.events("p2p_block_coinbase").is_empty());
        let observations = peer.events("p2p_block_coinbase_unverified");
        assert_eq!(observations.len(), 2);
        assert!(
            observations
                .iter()
                .all(|line| line["miner_script"].is_string())
        );
        assert_eq!(
            observations[0]["consensus_hash"],
            observations[1]["consensus_hash"]
        );
    }

    /// With no relay nothing judges the block, so receiving it is all there is.
    #[tokio::test]
    async fn without_a_relay_a_received_block_keeps_its_reward() {
        let (good, _) = good_and_bad();
        let mut peer = TestPeer::start("no-relay", scored_config()).await;

        peer.deliver(&good).await;

        assert_eq!(peer.score_reasons(), ["block_received"]);
    }

    /// Message level: a real v4 `tx` reaches the tx arm and leaves the cache and
    /// the feed untouched; a v6 sent next is cached and fed under Zebra's wtxid
    /// with its full payload. Every check runs after a ping/pong barrier, which
    /// the peer answers only after handling each earlier message.
    #[tokio::test]
    async fn a_v4_tx_message_is_neither_cached_nor_fed_and_a_v6_is() {
        use crate::wtxid::v6_equivalence::{V6_AUTHDIGEST_DISPLAY, V6_TXID_DISPLAY};
        use sovright_relay::{MempoolProvider, TxFeedRecord};
        use sovright_relay_sidecar::mempool_sync::wtxid_from_display_hex;

        let feed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        feed.set_nonblocking(true).unwrap();
        let mut config = peer_test_config();
        config.tx_feed_addr = Some(feed.local_addr().unwrap());
        // The v6 fixture is 12,322 bytes; the default test cache (4096) would
        // drop it as too large and fail the positive control for that reason.
        let cache = crate::tx_cache::TxCacheConfig {
            max_entries: 8,
            max_bytes: 65_536,
            max_tx_bytes: 32_768,
        };
        assert!(v6_tx().len() <= cache.max_tx_bytes && v6_tx().len() <= cache.max_bytes);
        let mut peer = TestPeer::start_with_cache("v4-tx-message", config, cache).await;
        let network = peer.network;

        write_message(&mut peer.stream, network, "tx", &v4_tx())
            .await
            .unwrap();
        assert!(peer.barrier().await.is_empty());
        assert_eq!(peer.cache.snapshot().entries, 0, "v4 is not cached");
        assert_eq!(peer.cache.wtxid_for_payload(&v4_tx()), None);
        assert!(accept_feed(&feed).is_empty(), "v4 does not reach the feed");
        let events = logged_events(&peer.log);
        assert!(events.iter().any(|event| event["event"] == "p2p_peer_error"
            && event["error"] == "received tx with no derivable wtxid; not cached"));
        assert!(
            !events
                .iter()
                .any(|event| event["event"] == "p2p_tx_received"
                    || event["event"] == "p2p_tx_feed_forwarded")
        );

        // Positive control. The oracle is Zebra's display txid/authdigest for
        // this fixture, not the from-bytes path under test.
        let zebra = wtxid_from_display_hex(V6_TXID_DISPLAY, V6_AUTHDIGEST_DISPLAY).unwrap();
        write_message(&mut peer.stream, network, "tx", &v6_tx())
            .await
            .unwrap();
        assert!(peer.barrier().await.is_empty());
        assert_eq!(peer.cache.get_wtxids(), vec![zebra]);
        assert_eq!(peer.cache.get_tx_data(&zebra), Some(v6_tx()));
        let lines = accept_feed(&feed);
        assert_eq!(lines.len(), 1, "exactly one feed record, the v6");
        assert_eq!(lines[0], TxFeedRecord::encode_line(zebra, &v6_tx()));
        let record = TxFeedRecord::parse_line(lines[0].trim_end()).unwrap();
        assert_eq!(record.wtxid, zebra);
        assert_eq!(record.tx_bytes, v6_tx(), "full payload");
    }

    async fn rejected_forwarding_handshake(
        command: &str,
        payload: &[u8],
        use_relay: bool,
    ) -> String {
        rejected_forwarding_handshake_with(peer_test_config(), command, payload, use_relay).await
    }

    async fn rejected_forwarding_handshake_with(
        mut config: Config,
        command: &str,
        payload: &[u8],
        use_relay: bool,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (relay, tx_feed) = if use_relay {
            config.relay_peers = vec!["127.0.0.1:9".parse().unwrap()];
            config.relay_auth_key = Some([42; 32]);
            (
                RelayBridge::from_config(&config, EventSink::new(None).unwrap())
                    .await
                    .unwrap(),
                None,
            )
        } else {
            (
                None,
                Some(TxFeedClient::new("127.0.0.1:9".parse().unwrap())),
            )
        };
        let log = temp_log_path("forwarding-handshake");
        let events = EventSink::new(Some(log.clone())).unwrap();
        let crawler = Crawler::new(&config, [address]);
        let task = tokio::spawn(run_peer(
            address, config, events, relay, None, tx_feed, crawler,
        ));
        let (mut stream, _) = listener.accept().await.unwrap();
        read_message(&mut stream, Network::Mainnet).await.unwrap();
        write_message(&mut stream, Network::Mainnet, command, payload)
            .await
            .unwrap();
        let mut task = task;
        let result = timeout(Duration::from_secs(2), &mut task).await;
        task.abort();
        if command == "reject" {
            assert!(fs::read_to_string(&log).unwrap().contains("p2p_reject"));
        }
        let _ = fs::remove_file(log);
        result
            .expect("unsafe handshake must be rejected promptly")
            .unwrap()
            .unwrap_err()
            .to_string()
    }

    #[tokio::test]
    async fn older_peer_is_allowed_only_on_observation_path() {
        let mut peer =
            TestPeer::start_with_remote_version("legacy-observation", peer_test_config(), 170160)
                .await;
        let inventory = numbered_inventory(crate::wire::MSG_BLOCK, 1);
        assert_eq!(peer.announce(&[inventory]).await, vec![inventory]);
    }

    #[tokio::test]
    async fn admitted_connection_cannot_renegotiate_to_an_old_version() {
        let mut config = peer_test_config();
        config.tx_feed_addr = Some("127.0.0.1:9".parse().unwrap());
        let mut peer = TestPeer::start("no-downgrade", config).await;
        let mut old = version_payload("127.0.0.1:8233".parse().unwrap(), Network::Mainnet);
        old[..4].copy_from_slice(&170160i32.to_le_bytes());
        write_message(&mut peer.stream, Network::Mainnet, "version", &old)
            .await
            .unwrap();
        let result = timeout(Duration::from_secs(2), &mut peer.task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(result, Err(IngressError::Wire(message)) if message.contains("duplicate version"))
        );
    }

    #[tokio::test]
    async fn forwarding_accepts_nu7_peer_and_requests_inventory() {
        let mut config = peer_test_config();
        config.tx_feed_addr = Some("127.0.0.1:9".parse().unwrap());
        let mut peer = TestPeer::start("nu7-forwarding", config).await;
        let inventory = numbered_inventory(crate::wire::MSG_BLOCK, 1);
        assert_eq!(peer.announce(&[inventory]).await, vec![inventory]);
    }

    #[tokio::test]
    async fn forwarding_rejects_pre_nu7_peer_even_before_activation() {
        let mut version = version_payload("127.0.0.1:8233".parse().unwrap(), Network::Mainnet);
        version[..4].copy_from_slice(&170160i32.to_le_bytes());
        for use_relay in [false, true] {
            for claimed_height in [0i32, i32::MAX] {
                let height_offset = version.len() - 5;
                version[height_offset..height_offset + 4]
                    .copy_from_slice(&claimed_height.to_le_bytes());
                assert!(
                    rejected_forwarding_handshake("version", &version, use_relay)
                        .await
                        .contains("170190")
                );
            }
        }
    }

    #[tokio::test]
    async fn forwarding_floor_override_admits_pre_nu7_peer() {
        let mut config = peer_test_config();
        config.tx_feed_addr = Some("127.0.0.1:9".parse().unwrap());
        config.forwarding_min_peer_version = Some(170_160);
        let mut peer = TestPeer::start_with_remote_version("floor-override", config, 170_160).await;
        let inventory = numbered_inventory(crate::wire::MSG_BLOCK, 1);
        assert_eq!(peer.announce(&[inventory]).await, vec![inventory]);
    }

    #[tokio::test]
    async fn forwarding_floor_override_still_rejects_peers_below_it() {
        let mut version = version_payload("127.0.0.1:8233".parse().unwrap(), Network::Mainnet);
        version[..4].copy_from_slice(&170_150i32.to_le_bytes());
        for use_relay in [false, true] {
            let mut config = peer_test_config();
            config.forwarding_min_peer_version = Some(170_160);
            let err =
                rejected_forwarding_handshake_with(config, "version", &version, use_relay).await;
            assert!(err.contains("170150 < 170160"), "{err}");
        }
    }

    #[tokio::test]
    async fn application_message_cannot_bypass_version_admission() {
        assert!(
            rejected_forwarding_handshake("inv", &[0], false)
                .await
                .contains("before handshake")
        );
    }

    #[tokio::test]
    async fn early_reject_is_logged_without_admitting_peer() {
        assert!(
            rejected_forwarding_handshake("reject", &[], false)
                .await
                .contains("before handshake")
        );
    }

    #[tokio::test]
    async fn verack_cannot_bypass_version_admission() {
        assert!(
            rejected_forwarding_handshake("verack", &[], false)
                .await
                .contains("before version")
        );
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
    async fn testnet_handshake_and_inventory_use_testnet_framing() {
        let mut config = peer_test_config();
        config.network = Network::Testnet;
        let mut peer = TestPeer::start("testnet-inventory", config).await;
        let inventory = numbered_inventory(crate::wire::MSG_BLOCK, 1);
        assert_eq!(peer.announce(&[inventory]).await, vec![inventory]);
        let rows = fs::read_to_string(&peer.log).unwrap();
        for row in rows.lines() {
            let value: serde_json::Value = serde_json::from_str(row).unwrap();
            assert_eq!(value["network"], "testnet");
        }
        // A valid mainnet frame on an established testnet connection is rejected.
        write_message(&mut peer.stream, Network::Mainnet, "ping", &[0; 8])
            .await
            .unwrap();
        let result = timeout(Duration::from_secs(5), &mut peer.task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(result, Err(IngressError::Wire(message)) if message.contains("unexpected magic"))
        );
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
        write_message(
            &mut peer.stream,
            Network::Mainnet,
            "notfound",
            &encode_inventory(&invs),
        )
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
        write_message(
            &mut peer.stream,
            Network::Mainnet,
            "notfound",
            &encode_inventory(&fresh),
        )
        .await
        .unwrap();
        assert!(
            peer.announce(&fresh).await.is_empty(),
            "unsolicited notfound must not free a slot"
        );
        write_message(&mut peer.stream, Network::Mainnet, "block", &payload)
            .await
            .unwrap();
        write_message(&mut peer.stream, Network::Mainnet, "tx", &v6_tx())
            .await
            .unwrap();
        assert_eq!(
            peer.announce(&fresh).await,
            fresh,
            "out-of-order responses must free their own slots"
        );
        assert!(peer.announce(&unanswered).await.is_empty());
        write_message(
            &mut peer.stream,
            Network::Mainnet,
            "notfound",
            &encode_inventory(&fresh),
        )
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
        write_message(
            &mut frame,
            Network::Mainnet,
            "inv",
            &encode_inventory(&invs),
        )
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
