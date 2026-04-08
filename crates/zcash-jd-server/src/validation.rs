//! Template validation for Full-Template mode

use crate::messages::SetFullTemplateJob;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Maximum number of known txids to track before clearing
const MAX_KNOWN_TXIDS: usize = 100_000;

/// Validation strictness for full templates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValidationLevel {
    /// Only verify pool payout output exists with minimum value
    #[default]
    Minimal,
    /// Verify pool payout + basic template structure (default)
    Standard,
    /// Full validation: verify all transactions are valid
    Strict,
}

impl ValidationLevel {
    /// Parse from string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "minimal" => Some(Self::Minimal),
            "standard" => Some(Self::Standard),
            "strict" => Some(Self::Strict),
            _ => None,
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Standard => "standard",
            Self::Strict => "strict",
        }
    }
}

impl std::fmt::Display for ValidationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ValidationLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}

/// Result of template validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Template is valid
    Valid,
    /// Template is invalid with reason
    Invalid(String),
    /// Need additional transaction data from client
    NeedTransactions(Vec<[u8; 32]>),
}

/// Validates full templates submitted by miners
pub struct TemplateValidator {
    /// Validation strictness level
    level: ValidationLevel,
    /// Pool's required payout script (scriptPubKey)
    pool_payout_script: Vec<u8>,
    /// Minimum pool payout value (zatoshis)
    min_pool_payout: u64,
    /// Known transaction IDs (from pool's mempool view)
    known_txids: HashSet<[u8; 32]>,
}

impl TemplateValidator {
    /// Create a new validator
    pub fn new(
        level: ValidationLevel,
        pool_payout_script: Vec<u8>,
        min_pool_payout: u64,
    ) -> Self {
        Self {
            level,
            pool_payout_script,
            min_pool_payout,
            known_txids: HashSet::new(),
        }
    }

    /// Update known transactions from pool's mempool
    ///
    /// When adding the batch would exceed capacity, evicts half the existing
    /// entries to make room rather than clearing all (which would cause
    /// unnecessary NeedTransactions requests for previously-known txids).
    pub fn update_known_txids(&mut self, txids: impl IntoIterator<Item = [u8; 32]>) {
        let txids_vec: Vec<[u8; 32]> = txids.into_iter().collect();
        if self.known_txids.len() + txids_vec.len() > MAX_KNOWN_TXIDS {
            // Evict half to amortize the cost of eviction
            let to_keep = self.known_txids.len() / 2;
            let to_remove: Vec<[u8; 32]> = self.known_txids.iter().skip(to_keep).copied().collect();
            for txid in to_remove {
                self.known_txids.remove(&txid);
            }
        }
        self.known_txids.extend(txids_vec);
    }

    /// Clear known transactions
    pub fn clear_known_txids(&mut self) {
        self.known_txids.clear();
    }

    /// Add a single known txid
    pub fn add_known_txid(&mut self, txid: [u8; 32]) {
        if self.known_txids.len() >= MAX_KNOWN_TXIDS {
            // Evict half rather than clearing all
            let to_keep = self.known_txids.len() / 2;
            let to_remove: Vec<[u8; 32]> = self.known_txids.iter().skip(to_keep).copied().collect();
            for t in to_remove {
                self.known_txids.remove(&t);
            }
        }
        self.known_txids.insert(txid);
    }

    /// Check if a txid is known
    pub fn is_txid_known(&self, txid: &[u8; 32]) -> bool {
        self.known_txids.contains(txid)
    }

    /// Get the validation level
    pub fn level(&self) -> ValidationLevel {
        self.level
    }

    /// Get the minimum pool payout
    #[allow(dead_code)]
    pub fn min_pool_payout(&self) -> u64 {
        self.min_pool_payout
    }

    /// Validate a full template job
    pub fn validate(&self, job: &SetFullTemplateJob) -> ValidationResult {
        // Always check pool payout in coinbase
        if !self.pool_payout_script.is_empty()
            && !self.validate_pool_payout(&job.coinbase_tx)
        {
            return ValidationResult::Invalid("Missing or insufficient pool payout".into());
        }
        if let Err(err) = Self::parse_transaction(&job.coinbase_tx) {
            return ValidationResult::Invalid(format!("invalid coinbase transaction: {}", err));
        }

        match self.level {
            ValidationLevel::Minimal => ValidationResult::Valid,
            ValidationLevel::Standard => self.validate_standard(job),
            ValidationLevel::Strict => self.validate_strict(job),
        }
    }

    /// Validate a coinbase transaction against pool payout requirements.
    pub fn validate_coinbase(&self, coinbase: &[u8]) -> Result<(), String> {
        if !self.pool_payout_script.is_empty() && !self.validate_pool_payout(coinbase) {
            return Err("Missing or insufficient pool payout".into());
        }
        Self::parse_transaction(coinbase).map_err(|err| format!("invalid coinbase transaction: {}", err))
    }

    /// Check if pool payout script appears in coinbase
    fn validate_pool_payout(&self, coinbase: &[u8]) -> bool {
        if self.pool_payout_script.is_empty() {
            return true;
        }
        let script = &self.pool_payout_script;
        if self.min_pool_payout == 0 {
            return coinbase.windows(script.len()).any(|w| w == script.as_slice());
        }

        // Best-effort parse: look for the payout script as a txout scriptPubKey and
        // verify the preceding value meets min_pool_payout. This is a heuristic and
        // does not fully parse Zcash transaction formats.
        for start in 0..=coinbase.len().saturating_sub(script.len()) {
            if &coinbase[start..start + script.len()] != script.as_slice() {
                continue;
            }
            if let Some(value) = Self::try_read_output_value(coinbase, start, script.len()) {
                if value >= self.min_pool_payout {
                    return true;
                }
            }
        }

        false
    }

    fn try_read_output_value(
        coinbase: &[u8],
        script_start: usize,
        script_len: usize,
    ) -> Option<u64> {
        // CompactSize length directly preceding script (1 byte)
        if script_start > 8 {
            let len = coinbase[script_start - 1] as usize;
            if len == script_len {
                let value_start = script_start - 1 - 8;
                let mut value_bytes = [0u8; 8];
                value_bytes.copy_from_slice(&coinbase[value_start..value_start + 8]);
                return Some(u64::from_le_bytes(value_bytes));
            }
        }

        // CompactSize length (0xfd + u16)
        if script_start >= 3 + 8 {
            let marker = coinbase[script_start - 3];
            if marker == 0xfd {
                let len = u16::from_le_bytes([coinbase[script_start - 2], coinbase[script_start - 1]])
                    as usize;
                if len == script_len {
                    let value_start = script_start - 3 - 8;
                    let mut value_bytes = [0u8; 8];
                    value_bytes.copy_from_slice(&coinbase[value_start..value_start + 8]);
                    return Some(u64::from_le_bytes(value_bytes));
                }
            }
        }

        // CompactSize length (0xfe + u32)
        if script_start >= 5 + 8 {
            let marker = coinbase[script_start - 5];
            if marker == 0xfe {
                let len = u32::from_le_bytes([
                    coinbase[script_start - 4],
                    coinbase[script_start - 3],
                    coinbase[script_start - 2],
                    coinbase[script_start - 1],
                ]) as usize;
                if len == script_len {
                    let value_start = script_start - 5 - 8;
                    let mut value_bytes = [0u8; 8];
                    value_bytes.copy_from_slice(&coinbase[value_start..value_start + 8]);
                    return Some(u64::from_le_bytes(value_bytes));
                }
            }
        }

        // CompactSize length (0xff + u64)
        if script_start >= 9 + 8 {
            let marker = coinbase[script_start - 9];
            if marker == 0xff {
                let len = u64::from_le_bytes([
                    coinbase[script_start - 8],
                    coinbase[script_start - 7],
                    coinbase[script_start - 6],
                    coinbase[script_start - 5],
                    coinbase[script_start - 4],
                    coinbase[script_start - 3],
                    coinbase[script_start - 2],
                    coinbase[script_start - 1],
                ]) as usize;
                if len == script_len {
                    let value_start = script_start - 9 - 8;
                    let mut value_bytes = [0u8; 8];
                    value_bytes.copy_from_slice(&coinbase[value_start..value_start + 8]);
                    return Some(u64::from_le_bytes(value_bytes));
                }
            }
        }

        None
    }

    /// Standard validation: check for missing transactions
    fn validate_standard(&self, job: &SetFullTemplateJob) -> ValidationResult {
        if job.tx_data.len() > job.tx_short_ids.len() {
            return ValidationResult::Invalid("too many transactions provided".into());
        }

        let mut provided_txids = HashSet::with_capacity(job.tx_data.len());
        for tx_data in &job.tx_data {
            if let Err(err) = Self::parse_transaction(tx_data) {
                return ValidationResult::Invalid(format!("invalid transaction data: {}", err));
            }
            let txid = Self::compute_txid(tx_data);
            if !job.tx_short_ids.contains(&txid) {
                return ValidationResult::Invalid("transaction data not referenced".into());
            }
            provided_txids.insert(txid);
        }

        // Check if we know all referenced transactions
        let missing: Vec<[u8; 32]> = job
            .tx_short_ids
            .iter()
            .filter(|txid| !self.known_txids.contains(*txid) && !provided_txids.contains(*txid))
            .copied()
            .collect();

        if !missing.is_empty() {
            return ValidationResult::NeedTransactions(missing);
        }

        match Self::compute_merkle_root(&job.coinbase_tx, &job.tx_short_ids) {
            Some(root) => {
                if root != job.merkle_root {
                    return ValidationResult::Invalid("invalid merkle root".into());
                }
            }
            None => {
                // Empty coinbase in Standard/Strict mode is invalid
                return ValidationResult::Invalid("empty coinbase transaction".into());
            }
        }

        ValidationResult::Valid
    }

    /// Strict validation: full transaction verification
    fn validate_strict(&self, job: &SetFullTemplateJob) -> ValidationResult {
        // First do standard validation
        match self.validate_standard(job) {
            ValidationResult::Valid => {}
            other => return other,
        }

        let txid_set: HashSet<[u8; 32]> = job.tx_short_ids.iter().copied().collect();
        for tx_data in &job.tx_data {
            if tx_data.is_empty() {
                return ValidationResult::Invalid("empty transaction data".into());
            }
            let txid = Self::compute_txid(tx_data);
            if !txid_set.contains(&txid) {
                return ValidationResult::Invalid("transaction data not referenced".into());
            }
        }

        ValidationResult::Valid
    }

    pub(crate) fn parse_transaction(data: &[u8]) -> Result<(), String> {
        if data.len() < 4 {
            return Err("transaction too short".into());
        }

        let mut cursor = 0usize;
        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        cursor += 4;
        if (version & 0x8000_0000) != 0 {
            if cursor + 4 > data.len() {
                return Err("missing version group id".into());
            }
            cursor += 4;
        }

        let vin_count = Self::read_compact_size(data, &mut cursor)?;
        for _ in 0..vin_count {
            if cursor + 36 > data.len() {
                return Err("input out of bounds".into());
            }
            cursor += 36;
            let script_len = Self::read_compact_size(data, &mut cursor)? as usize;
            if cursor + script_len + 4 > data.len() {
                return Err("scriptSig out of bounds".into());
            }
            cursor += script_len;
            cursor += 4;
        }

        let vout_count = Self::read_compact_size(data, &mut cursor)?;
        for _ in 0..vout_count {
            if cursor + 8 > data.len() {
                return Err("output value out of bounds".into());
            }
            cursor += 8;
            let script_len = Self::read_compact_size(data, &mut cursor)? as usize;
            if cursor + script_len > data.len() {
                return Err("output script out of bounds".into());
            }
            cursor += script_len;
        }

        if cursor + 4 > data.len() {
            return Err("missing lock_time".into());
        }
        cursor += 4;
        if (version & 0x8000_0000) != 0 {
            if cursor + 4 > data.len() {
                return Err("missing expiry_height".into());
            }
            cursor += 4;
        }

        if cursor > data.len() {
            return Err("transaction parse overflow".into());
        }

        Ok(())
    }

    fn read_compact_size(data: &[u8], cursor: &mut usize) -> Result<u64, String> {
        zcash_pool_common::read_compact_size(data, cursor)
            .map_err(|e| e.to_string())
    }

    pub(crate) fn compute_txid(data: &[u8]) -> [u8; 32] {
        let hash1 = Sha256::digest(data);
        let hash2 = Sha256::digest(hash1);
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&hash2);
        txid
    }

    pub(crate) fn compute_merkle_root(coinbase: &[u8], txids: &[[u8; 32]]) -> Option<[u8; 32]> {
        if coinbase.is_empty() {
            return None;
        }

        let mut all_txids = Vec::with_capacity(1 + txids.len());
        all_txids.push(Self::compute_txid(coinbase));
        all_txids.extend_from_slice(txids);

        Some(Self::merkle_root_from_txids(&all_txids))
    }

    fn merkle_root_from_txids(txids: &[[u8; 32]]) -> [u8; 32] {
        if txids.is_empty() {
            return [0u8; 32];
        }

        let mut layer: Vec<[u8; 32]> = txids.to_vec();
        while layer.len() > 1 {
            let mut next = Vec::with_capacity(layer.len().div_ceil(2));
            let mut i = 0;
            while i < layer.len() {
                let left = layer[i];
                let right = if i + 1 < layer.len() { layer[i + 1] } else { left };
                let mut data = [0u8; 64];
                data[..32].copy_from_slice(&left);
                data[32..].copy_from_slice(&right);
                next.push(Self::compute_txid(&data));
                i += 2;
            }
            layer = next;
        }
        layer[0]
    }
}

impl Default for TemplateValidator {
    fn default() -> Self {
        Self::new(ValidationLevel::default(), vec![], 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::SetFullTemplateJob;

    fn minimal_tx() -> Vec<u8> {
        minimal_tx_with_script(&[0x51])
    }

    fn minimal_tx_with_script(script: &[u8]) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes()); // version
        tx.push(0x01); // vin count
        tx.extend_from_slice(&[0u8; 32]); // prevout hash
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // prevout index
        tx.push(0x01); // scriptSig length
        tx.push(0x00); // scriptSig
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        tx.push(0x01); // vout count
        tx.extend_from_slice(&0u64.to_le_bytes()); // value
        if script.len() < 0xfd {
            tx.push(script.len() as u8);
        } else {
            tx.push(0xfd);
            tx.extend_from_slice(&(script.len() as u16).to_le_bytes());
        }
        tx.extend_from_slice(script);
        tx.extend_from_slice(&0u32.to_le_bytes()); // lock_time
        tx
    }

    #[test]
    fn test_validation_level_from_str() {
        assert_eq!(
            ValidationLevel::parse("minimal"),
            Some(ValidationLevel::Minimal)
        );
        assert_eq!(
            ValidationLevel::parse("STANDARD"),
            Some(ValidationLevel::Standard)
        );
        assert_eq!(
            ValidationLevel::parse("Strict"),
            Some(ValidationLevel::Strict)
        );
        assert_eq!(ValidationLevel::parse("unknown"), None);
    }

    #[test]
    fn test_validation_level_display() {
        assert_eq!(format!("{}", ValidationLevel::Minimal), "minimal");
        assert_eq!(format!("{}", ValidationLevel::Standard), "standard");
        assert_eq!(format!("{}", ValidationLevel::Strict), "strict");
    }

    #[test]
    fn test_validation_level_default() {
        let level: ValidationLevel = Default::default();
        assert_eq!(level, ValidationLevel::Minimal);
    }

    #[test]
    fn test_validation_result_variants() {
        let valid = ValidationResult::Valid;
        assert_eq!(valid, ValidationResult::Valid);

        let invalid = ValidationResult::Invalid("missing payout".to_string());
        assert_eq!(
            invalid,
            ValidationResult::Invalid("missing payout".to_string())
        );

        let need_tx = ValidationResult::NeedTransactions(vec![[0u8; 32], [1u8; 32]]);
        if let ValidationResult::NeedTransactions(txids) = need_tx {
            assert_eq!(txids.len(), 2);
        } else {
            panic!("Expected NeedTransactions variant");
        }
    }

    // =========================================================================
    // TemplateValidator Tests
    // =========================================================================

    fn make_test_job() -> SetFullTemplateJob {
        let mut job = SetFullTemplateJob {
            channel_id: 1,
            request_id: 1,
            mining_job_token: vec![0x01, 0x02, 0x03],
            version: 5,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: minimal_tx(),
            time: 1700000000,
            bits: 0x1d00ffff,
            tx_short_ids: vec![],
            tx_data: vec![],
        };
        if let Some(root) = TemplateValidator::compute_merkle_root(&job.coinbase_tx, &[]) {
            job.merkle_root = root;
        }
        job
    }

    fn update_merkle_root(job: &mut SetFullTemplateJob) {
        if let Some(root) =
            TemplateValidator::compute_merkle_root(&job.coinbase_tx, &job.tx_short_ids)
        {
            job.merkle_root = root;
        }
    }

    #[test]
    fn test_minimal_validation_accepts_any() {
        let validator = TemplateValidator::new(ValidationLevel::Minimal, vec![], 0);
        let job = make_test_job();
        assert_eq!(validator.validate(&job), ValidationResult::Valid);
    }

    #[test]
    fn test_standard_validation_with_unknown_txids() {
        let validator = TemplateValidator::new(ValidationLevel::Standard, vec![], 0);
        let mut job = make_test_job();
        job.tx_short_ids = vec![[0x11; 32], [0x22; 32]];
        update_merkle_root(&mut job);

        match validator.validate(&job) {
            ValidationResult::NeedTransactions(missing) => {
                assert_eq!(missing.len(), 2);
            }
            _ => panic!("Expected NeedTransactions"),
        }
    }

    #[test]
    fn test_standard_validation_with_known_txids() {
        let mut validator = TemplateValidator::new(ValidationLevel::Standard, vec![], 0);
        validator.add_known_txid([0x11; 32]);
        validator.add_known_txid([0x22; 32]);

        let mut job = make_test_job();
        job.tx_short_ids = vec![[0x11; 32], [0x22; 32]];
        update_merkle_root(&mut job);

        assert_eq!(validator.validate(&job), ValidationResult::Valid);
    }

    #[test]
    fn test_standard_validation_with_provided_tx_data() {
        let validator = TemplateValidator::new(ValidationLevel::Standard, vec![], 0);
        let mut job = make_test_job();
        let tx1 = minimal_tx();
        let tx2 = minimal_tx_with_script(&[0x52]);
        job.tx_short_ids = vec![
            TemplateValidator::compute_txid(&tx1),
            TemplateValidator::compute_txid(&tx2),
        ];
        job.tx_data = vec![tx1, tx2];
        update_merkle_root(&mut job);

        assert_eq!(validator.validate(&job), ValidationResult::Valid);
    }

    #[test]
    fn test_standard_validation_rejects_unreferenced_tx_data() {
        let validator = TemplateValidator::new(ValidationLevel::Standard, vec![], 0);
        let mut job = make_test_job();
        let tx = minimal_tx();
        job.tx_short_ids = vec![[0x11; 32]];
        job.tx_data = vec![tx];
        update_merkle_root(&mut job);

        assert_eq!(
            validator.validate(&job),
            ValidationResult::Invalid("transaction data not referenced".into())
        );
    }

    #[test]
    fn test_pool_payout_validation() {
        let payout_script = vec![0x76, 0xa9, 0x14, 0xde, 0xad, 0xbe, 0xef];
        let validator =
            TemplateValidator::new(ValidationLevel::Minimal, payout_script.clone(), 0);

        // Coinbase without payout script
        let mut job = make_test_job();
        job.coinbase_tx = minimal_tx();
        assert!(matches!(
            validator.validate(&job),
            ValidationResult::Invalid(_)
        ));

        // Coinbase with payout script
        job.coinbase_tx = minimal_tx_with_script(&payout_script);
        update_merkle_root(&mut job);
        assert_eq!(validator.validate(&job), ValidationResult::Valid);
    }

    #[test]
    fn test_update_known_txids() {
        let mut validator = TemplateValidator::default();
        assert!(!validator.is_txid_known(&[0x11; 32]));

        validator.update_known_txids([[0x11; 32], [0x22; 32]]);
        assert!(validator.is_txid_known(&[0x11; 32]));
        assert!(validator.is_txid_known(&[0x22; 32]));

        validator.clear_known_txids();
        assert!(!validator.is_txid_known(&[0x11; 32]));
    }

    #[test]
    fn test_validator_default() {
        let validator = TemplateValidator::default();
        assert_eq!(validator.level(), ValidationLevel::Minimal);
        assert!(!validator.is_txid_known(&[0x00; 32]));
    }

    #[test]
    fn test_strict_validation() {
        let mut validator = TemplateValidator::new(ValidationLevel::Strict, vec![], 0);
        validator.add_known_txid([0x11; 32]);

        let mut job = make_test_job();
        job.tx_short_ids = vec![[0x11; 32]];
        update_merkle_root(&mut job);

        assert_eq!(validator.validate(&job), ValidationResult::Valid);
    }

    #[test]
    fn test_strict_validation_with_missing_txids() {
        let validator = TemplateValidator::new(ValidationLevel::Strict, vec![], 0);
        let mut job = make_test_job();
        job.tx_short_ids = vec![[0x11; 32], [0x22; 32]];

        match validator.validate(&job) {
            ValidationResult::NeedTransactions(missing) => {
                assert_eq!(missing.len(), 2);
            }
            _ => panic!("Expected NeedTransactions"),
        }
    }

    #[test]
    fn test_pool_payout_checked_before_level_validation() {
        // Even at Minimal level, pool payout should be checked first
        let payout_script = vec![0xde, 0xad, 0xbe, 0xef];
        let validator = TemplateValidator::new(ValidationLevel::Minimal, payout_script, 0);

        let job = make_test_job();
        // Coinbase doesn't contain the payout script
        match validator.validate(&job) {
            ValidationResult::Invalid(msg) => {
                assert!(msg.contains("pool payout"));
            }
            _ => panic!("Expected Invalid result"),
        }
    }

    #[test]
    fn test_empty_payout_script_skips_validation() {
        // Empty payout script should skip payout validation
        let validator = TemplateValidator::new(ValidationLevel::Minimal, vec![], 0);
        let job = make_test_job();
        assert_eq!(validator.validate(&job), ValidationResult::Valid);
    }

    #[test]
    fn test_partial_known_txids() {
        let mut validator = TemplateValidator::new(ValidationLevel::Standard, vec![], 0);
        validator.add_known_txid([0x11; 32]);
        // 0x22 is unknown

        let mut job = make_test_job();
        job.tx_short_ids = vec![[0x11; 32], [0x22; 32]];

        match validator.validate(&job) {
            ValidationResult::NeedTransactions(missing) => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], [0x22; 32]);
            }
            _ => panic!("Expected NeedTransactions for partial known txids"),
        }
    }
}
