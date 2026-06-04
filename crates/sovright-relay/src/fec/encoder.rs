//! FEC encoder using Reed-Solomon erasure coding

use reed_solomon_erasure::galois_8::ReedSolomon;

use super::FecError;

/// Forward Error Correction encoder
///
/// Encodes data into data shards + parity shards using Reed-Solomon.
/// Can reconstruct original data if at least `data_shards` of the
/// total shards are received.
pub struct FecEncoder {
    rs: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
}

impl FecEncoder {
    /// Create a new encoder with specified shard counts
    ///
    /// # Arguments
    /// * `data_shards` - Number of data shards (original data split into this many pieces)
    /// * `parity_shards` - Number of parity shards (redundancy for recovery)
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self, FecError> {
        if data_shards == 0 {
            return Err(FecError::InvalidConfiguration(
                "data_shards must be > 0".into(),
            ));
        }
        if parity_shards == 0 {
            return Err(FecError::InvalidConfiguration(
                "parity_shards must be > 0".into(),
            ));
        }

        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| FecError::InvalidConfiguration(e.to_string()))?;

        Ok(Self {
            rs,
            data_shards,
            parity_shards,
        })
    }

    /// Encode data into shards
    ///
    /// Returns a vector of shards: [data_shard_0, ..., data_shard_n, parity_0, ..., parity_m]
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, FecError> {
        if data.is_empty() {
            return Err(FecError::InvalidConfiguration(
                "data cannot be empty".into(),
            ));
        }

        let total_shards = self.data_shards + self.parity_shards;

        // Calculate shard size (pad data to be divisible by data_shards)
        let shard_size = data.len().div_ceil(self.data_shards);

        // Create shards with padding
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total_shards);

        // Split data into data shards
        for i in 0..self.data_shards {
            let start = i * shard_size;
            let end = std::cmp::min(start + shard_size, data.len());

            let mut shard = vec![0u8; shard_size];
            if start < data.len() {
                let copy_len = end - start;
                shard[..copy_len].copy_from_slice(&data[start..end]);
            }
            shards.push(shard);
        }

        // Add empty parity shards
        for _ in 0..self.parity_shards {
            shards.push(vec![0u8; shard_size]);
        }

        // Encode parity
        self.rs
            .encode(&mut shards)
            .map_err(|e| FecError::EncodingFailed(e.to_string()))?;

        Ok(shards)
    }

    /// Get the number of data shards
    pub fn data_shards(&self) -> usize {
        self.data_shards
    }

    /// Get the number of parity shards
    pub fn parity_shards(&self) -> usize {
        self.parity_shards
    }

    /// Get total number of shards
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }
}
