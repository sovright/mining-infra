//! Template polling with change detection

use forge_sidecar::rpc::{BlockTemplate, ZebraRpc};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Template change event
#[derive(Debug, Clone)]
pub struct TemplateUpdate {
    pub template: BlockTemplate,
    #[allow(dead_code)] // Will be used for smarter update logic
    pub prev_hash_changed: bool,
}

/// Template poller that detects new blocks
pub struct TemplatePoller {
    rpc: Arc<ZebraRpc>,
    poll_interval: Duration,
    last_prev_hash: Option<String>,
    last_height: Option<u64>,
}

impl TemplatePoller {
    pub fn new(rpc: Arc<ZebraRpc>, poll_interval: Duration) -> Self {
        Self {
            rpc,
            poll_interval,
            last_prev_hash: None,
            last_height: None,
        }
    }

    /// Run the polling loop, sending updates to the channel
    pub async fn run(mut self, tx: mpsc::Sender<TemplateUpdate>) {
        loop {
            match self.rpc.get_block_template().await {
                Ok(template) => {
                    let prev_hash_changed =
                        self.last_prev_hash.as_ref() != Some(&template.previous_block_hash);
                    let height_changed = self.last_height != Some(template.height);

                    if prev_hash_changed || height_changed {
                        info!(
                            height = template.height,
                            tx_count = template.transactions.len(),
                            prev_hash_changed,
                            "New block template"
                        );

                        self.last_prev_hash = Some(template.previous_block_hash.clone());
                        self.last_height = Some(template.height);

                        let update = TemplateUpdate {
                            template,
                            prev_hash_changed,
                        };

                        if tx.send(update).await.is_err() {
                            warn!("Template receiver dropped, stopping poller");
                            break;
                        }
                    } else {
                        debug!(height = template.height, "Template unchanged");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to get block template");
                }
            }

            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_update_creation() {
        let template = BlockTemplate {
            version: 4,
            previous_block_hash: "abc".to_string(),
            cur_time: 0,
            bits: "1f07ffff".to_string(),
            height: 100,
            transactions: vec![],
            coinbase_txn: None,
            default_roots: None,
        };

        let update = TemplateUpdate {
            template: template.clone(),
            prev_hash_changed: true,
        };

        assert!(update.prev_hash_changed);
        assert_eq!(update.template.height, 100);
    }
}
