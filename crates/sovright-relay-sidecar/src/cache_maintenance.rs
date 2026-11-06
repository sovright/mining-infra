//! Canonical-chain confirmation tracking for the bounded reconstruction cache.

use crate::rpc::ZebraRpc;
use sovright_relay::{TxCache, TxId};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

type Error = Box<dyn std::error::Error + Send + Sync>;
const MAX_SCAN_BLOCKS: u64 = 32;
const MAX_RECENT_TXIDS: usize = 262_144;

/// Anchor is advanced only after a complete, stable canonical observation.
#[derive(Default)]
pub struct MaintenanceState {
    anchor: Option<(u64, String)>,
    recent: VecDeque<(u64, Vec<TxId>, Instant)>,
}

fn txid_from_display(value: &str) -> Result<TxId, Error> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes)?;
    bytes.reverse();
    Ok(TxId::from_bytes(bytes))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

impl MaintenanceState {
    /// Observe canonical inclusion, protect pending reappearances, then expire
    /// sufficiently old/deep confirmations. RPC failure never purges payloads.
    pub async fn poll_once(
        &mut self,
        rpc: &ZebraRpc,
        cache: &TxCache,
        now: Instant,
        grace: Duration,
        min_confirmations: u64,
    ) -> Result<usize, Error> {
        let started = Instant::now();
        let tip = rpc.get_blockchain_info().await?;
        if !valid_hash(&tip.best_block_hash) {
            return Err("invalid tip hash".into());
        }
        let reorg = match &self.anchor {
            Some((height, hash)) if *height <= tip.blocks => {
                rpc.get_block_hash(*height).await?.to_lowercase() != hash.to_lowercase()
            }
            Some(_) => true,
            None => false,
        };
        let gap = self
            .anchor
            .as_ref()
            .is_some_and(|(height, _)| tip.blocks.saturating_sub(*height) > MAX_SCAN_BLOCKS);
        let start = match &self.anchor {
            Some((height, _)) if !reorg && !gap => height.saturating_add(1),
            _ => tip.blocks.saturating_sub(MAX_SCAN_BLOCKS - 1),
        };
        let mut confirmed = VecDeque::new();
        let mut scanned_txids = 0;
        let mut last_hash: Option<String> = if !reorg && !gap {
            self.anchor.as_ref().map(|(_, hash)| hash.clone())
        } else {
            None
        };
        for height in start..=tip.blocks {
            let canonical = rpc.get_block_hash(height).await?;
            if !valid_hash(&canonical) {
                return Err("invalid canonical hash".into());
            }
            let block = rpc.get_cache_block(&canonical).await?;
            if block.height != height || !block.hash.eq_ignore_ascii_case(&canonical) {
                return Err("canonical block identity mismatch".into());
            }
            if let Some(previous) = &last_hash
                && !block
                    .previous_block_hash
                    .as_ref()
                    .is_some_and(|h| h.eq_ignore_ascii_case(previous))
            {
                return Err("canonical scan parent mismatch".into());
            }
            if height == tip.blocks && !block.hash.eq_ignore_ascii_case(&tip.best_block_hash) {
                return Err("canonical scan tip mismatch".into());
            }
            let txids = block
                .tx
                .iter()
                .map(|s| txid_from_display(s))
                .collect::<Result<Vec<_>, _>>()?;
            if txids.len() > MAX_RECENT_TXIDS {
                return Err("block exceeds bounded transaction tracking".into());
            }
            scanned_txids += txids.len();
            confirmed.push_back((height, txids));
            while scanned_txids > MAX_RECENT_TXIDS {
                if let Some((_, dropped)) = confirmed.pop_front() {
                    scanned_txids -= dropped.len();
                }
            }
            last_hash = Some(block.hash);
        }
        let pending = rpc
            .get_raw_mempool()
            .await?
            .iter()
            .map(|s| txid_from_display(s))
            .collect::<Result<Vec<_>, _>>()?;
        let after = rpc.get_blockchain_info().await?;
        if after.blocks != tip.blocks
            || !after
                .best_block_hash
                .eq_ignore_ascii_case(&tip.best_block_hash)
        {
            return Err("chain changed during cache-maintenance observation".into());
        }
        // No await between stable observation and cache mutation. A deep reorg
        // or skipped catch-up conservatively removes all confirmation metadata.
        let observed_now = now
            .checked_add(started.elapsed())
            .ok_or("monotonic clock overflow")?;
        if reorg || gap {
            cache.clear_confirmations();
            self.recent.clear();
        }
        for (height, txids) in confirmed {
            self.recent.push_back((height, txids, observed_now));
        }
        // Retain a bounded canonical window so a delayed tx feed insertion can
        // still be recognized as confirmed without refetching old blocks.
        while self.recent.len() > MAX_SCAN_BLOCKS as usize
            || self
                .recent
                .iter()
                .map(|(_, txids, _)| txids.len())
                .sum::<usize>()
                > MAX_RECENT_TXIDS
        {
            self.recent.pop_front();
        }
        for (height, txids, observed_at) in &self.recent {
            cache.mark_confirmed(txids, *height, *observed_at);
        }
        cache.restore_pending(&pending);
        let removed = cache.evict_confirmed(tip.blocks, observed_now, grace, min_confirmations);
        self.anchor = Some((tip.blocks, tip.best_block_hash));
        Ok(removed)
    }
}

/// Opt-in independent maintenance task, outside reconstruction/submission paths.
pub async fn run_cache_maintenance(
    rpc: Arc<ZebraRpc>,
    cache: TxCache,
    interval: Duration,
    grace: Duration,
    min_confirmations: u64,
) {
    let mut state = MaintenanceState::default();
    let mut ticks = tokio::time::interval(interval.max(Duration::from_millis(100)));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticks.tick().await;
        match state
            .poll_once(&rpc, &cache, Instant::now(), grace, min_confirmations)
            .await
        {
            Ok(removed) if removed > 0 => {
                tracing::info!(removed, "Confirmed transaction cache entries evicted")
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "Transaction cache maintenance deferred; payloads retained")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::server::{RpcModule, ServerBuilder};
    use serde_json::json;
    use sovright_relay::{AuthDigest, MempoolProvider, TxCacheConfig, WtxId};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Mock {
        tip: u64,
        fork: u64,
        fail_blocks: bool,
        unstable: bool,
        info_calls: usize,
        block_calls: usize,
        info_delay_ms: u64,
        pending: Vec<String>,
    }
    fn hash(height: u64, fork: u64) -> String {
        format!("{:064x}", height + fork * 10000)
    }
    fn txid() -> TxId {
        TxId::from_bytes([7; 32])
    }
    fn display_txid() -> String {
        hex::encode(txid().as_bytes().iter().rev().copied().collect::<Vec<_>>())
    }
    fn cache() -> (TxCache, WtxId) {
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 10,
            max_bytes: 100,
            max_tx_bytes: 100,
        });
        let wtxid = WtxId::new(txid(), AuthDigest::from_bytes([8; 32]));
        cache.insert(wtxid, vec![1, 2, 3]);
        (cache, wtxid)
    }
    async fn server(mock: Arc<Mutex<Mock>>) -> (ZebraRpc, jsonrpsee::server::ServerHandle) {
        let mut module = RpcModule::new(mock);
        module
            .register_method("getblockchaininfo", |_, m, _| {
                let mut m = m.lock().unwrap();
                std::thread::sleep(Duration::from_millis(m.info_delay_ms));
                m.info_calls += 1;
                let tip = m.tip + u64::from(m.unstable && m.info_calls % 2 == 0);
                json!({"blocks":tip,"bestblockhash":hash(tip,m.fork)})
            })
            .unwrap();
        module
            .register_method("getblockhash", |p, m, _| {
                let (h,): (u64,) = p.parse()?;
                let m = m.lock().unwrap();
                Ok::<_, jsonrpsee::types::ErrorObjectOwned>(hash(h, m.fork))
            })
            .unwrap();
        module.register_method("getblock",|p,m,_| {
            let (h,_):(String,u8)=p.parse()?;let mut m=m.lock().unwrap();m.block_calls+=1;
            if m.fail_blocks { return Err(jsonrpsee::types::ErrorObjectOwned::owned(-1,"unavailable",None::<()>)); }
            let n=u64::from_str_radix(&h,16).unwrap()-m.fork*10000;
            Ok(json!({"hash":h,"height":n,"previousblockhash":hash(n.saturating_sub(1),m.fork),"tx":[display_txid()]}))
        }).unwrap();
        module
            .register_method("getrawmempool", |_, m, _| m.lock().unwrap().pending.clone())
            .unwrap();
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let handle = server.start(module);
        (
            ZebraRpc::new(&format!("http://{addr}")).await.unwrap(),
            handle,
        )
    }
    #[tokio::test]
    async fn stable_confirmation_retains_during_grace_then_expires() {
        let mock = Arc::new(Mutex::new(Mock {
            tip: 40,
            ..Default::default()
        }));
        let (rpc, _handle) = server(mock).await;
        let (cache, wtxid) = cache();
        let mut state = MaintenanceState::default();
        let now = Instant::now();
        state
            .poll_once(&rpc, &cache, now, Duration::from_secs(600), 12)
            .await
            .unwrap();
        assert!(cache.contains(&wtxid));
        state
            .poll_once(
                &rpc,
                &cache,
                now + Duration::from_secs(601),
                Duration::from_secs(600),
                12,
            )
            .await
            .unwrap();
        assert!(!cache.contains(&wtxid));
    }
    #[tokio::test]
    async fn unavailable_or_unstable_snapshot_cannot_evict() {
        let mock = Arc::new(Mutex::new(Mock {
            tip: 40,
            ..Default::default()
        }));
        let (rpc, _handle) = server(Arc::clone(&mock)).await;
        let (cache, wtxid) = cache();
        let mut state = MaintenanceState::default();
        let now = Instant::now();
        state
            .poll_once(&rpc, &cache, now, Duration::from_secs(600), 12)
            .await
            .unwrap();
        mock.lock().unwrap().unstable = true;
        assert!(
            state
                .poll_once(
                    &rpc,
                    &cache,
                    now + Duration::from_secs(601),
                    Duration::ZERO,
                    1
                )
                .await
                .is_err()
        );
        assert!(cache.contains(&wtxid));
        mock.lock().unwrap().unstable = false;
        mock.lock().unwrap().tip = 41;
        mock.lock().unwrap().fail_blocks = true;
        assert!(
            state
                .poll_once(
                    &rpc,
                    &cache,
                    now + Duration::from_secs(601),
                    Duration::ZERO,
                    1
                )
                .await
                .is_err()
        );
        assert!(cache.contains(&wtxid));
    }
    #[tokio::test]
    async fn mempool_reappearance_clears_confirmations() {
        let mock = Arc::new(Mutex::new(Mock {
            tip: 40,
            ..Default::default()
        }));
        let (rpc, _handle) = server(Arc::clone(&mock)).await;
        let (cache, wtxid) = cache();
        let mut state = MaintenanceState::default();
        let now = Instant::now();
        state
            .poll_once(&rpc, &cache, now, Duration::from_secs(600), 12)
            .await
            .unwrap();
        mock.lock().unwrap().pending = vec![display_txid()];
        state
            .poll_once(
                &rpc,
                &cache,
                now + Duration::from_secs(601),
                Duration::from_secs(600),
                12,
            )
            .await
            .unwrap();
        assert!(cache.contains(&wtxid));
    }
    #[tokio::test]
    async fn same_height_reorg_resets_grace_and_catchup_is_bounded() {
        let mock = Arc::new(Mutex::new(Mock {
            tip: 100000,
            ..Default::default()
        }));
        let (rpc, _handle) = server(Arc::clone(&mock)).await;
        let (cache, wtxid) = cache();
        let mut state = MaintenanceState::default();
        let now = Instant::now();
        state
            .poll_once(&rpc, &cache, now, Duration::from_secs(600), 12)
            .await
            .unwrap();
        assert_eq!(mock.lock().unwrap().block_calls, 32);
        mock.lock().unwrap().fork = 1;
        state
            .poll_once(
                &rpc,
                &cache,
                now + Duration::from_secs(601),
                Duration::from_secs(600),
                12,
            )
            .await
            .unwrap();
        assert!(cache.contains(&wtxid));
        assert_eq!(mock.lock().unwrap().block_calls, 64);
    }
    #[tokio::test]
    async fn malformed_mempool_and_rollback_never_use_old_confirmation_age() {
        let mock = Arc::new(Mutex::new(Mock {
            tip: 40,
            ..Default::default()
        }));
        let (rpc, _handle) = server(Arc::clone(&mock)).await;
        let (cache, wtxid) = cache();
        let mut state = MaintenanceState::default();
        let now = Instant::now();
        state
            .poll_once(&rpc, &cache, now, Duration::from_secs(600), 12)
            .await
            .unwrap();
        mock.lock().unwrap().pending = vec!["malformed".to_string()];
        assert!(
            state
                .poll_once(
                    &rpc,
                    &cache,
                    now + Duration::from_secs(601),
                    Duration::from_secs(600),
                    12
                )
                .await
                .is_err()
        );
        assert!(cache.contains(&wtxid));
        mock.lock().unwrap().pending.clear();
        mock.lock().unwrap().tip = 39;
        state
            .poll_once(
                &rpc,
                &cache,
                now + Duration::from_secs(601),
                Duration::from_secs(600),
                12,
            )
            .await
            .unwrap();
        assert!(cache.contains(&wtxid));
        assert_eq!(state.anchor.as_ref().unwrap().0, 39);
    }
    #[tokio::test]
    async fn late_insertions_are_classified_from_retained_canonical_window() {
        let mock = Arc::new(Mutex::new(Mock {
            tip: 40,
            ..Default::default()
        }));
        let (rpc, _handle) = server(mock).await;
        let (cache, wtxid) = cache();
        let mut state = MaintenanceState::default();
        let now = Instant::now();
        state
            .poll_once(&rpc, &cache, now, Duration::ZERO, 1)
            .await
            .unwrap();
        assert!(!cache.contains(&wtxid));
        cache.insert(wtxid, vec![1, 2, 3]);
        state
            .poll_once(
                &rpc,
                &cache,
                now + Duration::from_secs(601),
                Duration::from_secs(600),
                12,
            )
            .await
            .unwrap();
        assert!(!cache.contains(&wtxid));
    }
    #[tokio::test]
    async fn successful_slow_observation_starts_grace_after_rpc_work() {
        let mock = Arc::new(Mutex::new(Mock {
            tip: 40,
            info_delay_ms: 20,
            ..Default::default()
        }));
        let (rpc, _handle) = server(mock).await;
        let (cache, wtxid) = cache();
        let mut state = MaintenanceState::default();
        let now = Instant::now();
        state
            .poll_once(&rpc, &cache, now, Duration::from_secs(1), 1)
            .await
            .unwrap();
        assert_eq!(
            cache.evict_confirmed(
                40,
                now + Duration::from_millis(1010),
                Duration::from_secs(1),
                1
            ),
            0
        );
        assert!(cache.contains(&wtxid));
    }
}
