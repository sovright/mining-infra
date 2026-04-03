//! Zcash block reward calculations.
//!
//! Implements the post-Blossom halving schedule and pool fee/reward splitting.

/// Post-Blossom halving interval (blocks).
pub const POST_BLOSSOM_HALVING_INTERVAL: u64 = 1_680_000;

/// Post-Blossom initial block subsidy in zatoshis (3.125 ZEC).
pub const POST_BLOSSOM_INITIAL_SUBSIDY: u64 = 312_500_000;

/// Default miner share of block subsidy (80%).
pub const DEFAULT_MINER_SHARE_PERCENT: u64 = 80;

/// Compute the block subsidy at a given height using the post-Blossom halving schedule.
///
/// The subsidy halves every `POST_BLOSSOM_HALVING_INTERVAL` blocks.
/// After 64 halvings, the subsidy is zero.
pub fn block_subsidy(height: u64) -> u64 {
    let halvings = height / POST_BLOSSOM_HALVING_INTERVAL;
    if halvings >= 64 {
        return 0;
    }
    POST_BLOSSOM_INITIAL_SUBSIDY >> halvings
}

/// Compute the miner's share of the block subsidy.
pub fn miner_reward(subsidy: u64, miner_share_percent: u64) -> u64 {
    subsidy * miner_share_percent / 100
}

/// Apply a pool fee percentage, returning the amount after the fee is deducted.
pub fn apply_pool_fee(amount: u64, fee_percent: u64) -> u64 {
    amount - (amount * fee_percent / 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_halving_era_subsidy() {
        assert_eq!(block_subsidy(1), 312_500_000);
        assert_eq!(block_subsidy(100_000), 312_500_000);
    }

    #[test]
    fn subsidy_halves_at_interval() {
        // Last block of first era
        assert_eq!(
            block_subsidy(POST_BLOSSOM_HALVING_INTERVAL - 1),
            312_500_000
        );
        // First block of second era
        assert_eq!(
            block_subsidy(POST_BLOSSOM_HALVING_INTERVAL),
            156_250_000
        );
        // Second halving
        assert_eq!(
            block_subsidy(2 * POST_BLOSSOM_HALVING_INTERVAL),
            78_125_000
        );
    }

    #[test]
    fn subsidy_zero_after_many_halvings() {
        assert_eq!(block_subsidy(64 * POST_BLOSSOM_HALVING_INTERVAL), 0);
        assert_eq!(block_subsidy(100 * POST_BLOSSOM_HALVING_INTERVAL), 0);
    }

    #[test]
    fn miner_reward_applies_percentage() {
        let subsidy = 312_500_000;
        assert_eq!(miner_reward(subsidy, 80), 250_000_000);
    }

    #[test]
    fn pool_fee_deducted_correctly() {
        let amount = 250_000_000;
        assert_eq!(apply_pool_fee(amount, 1), 247_500_000);
    }
}
