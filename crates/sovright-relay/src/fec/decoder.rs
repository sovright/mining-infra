//! FEC decoder using Reed-Solomon erasure coding

use reed_solomon_erasure::galois_8::ReedSolomon;

use super::FecError;

/// Forward Error Correction decoder
///
/// Reconstructs original data from received shards, even if some are missing.
pub struct FecDecoder {
    rs: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
}

impl FecDecoder {
    /// Create a new decoder with specified shard counts
    ///
    /// Must match the encoder configuration.
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

    /// Decode shards back to original data
    ///
    /// # Arguments
    /// * `shards` - Vector of optional shards (None for missing/lost shards)
    /// * `original_len` - Original data length (needed to trim padding)
    ///
    /// # Returns
    /// Original data if enough shards are present, error otherwise
    pub fn decode(
        &self,
        mut shards: Vec<Option<Vec<u8>>>,
        original_len: usize,
    ) -> Result<Vec<u8>, FecError> {
        let total_shards = self.data_shards + self.parity_shards;

        if shards.len() != total_shards {
            return Err(FecError::InvalidConfiguration(format!(
                "expected {} shards, got {}",
                total_shards,
                shards.len()
            )));
        }

        // Count available shards
        let available = shards.iter().filter(|s| s.is_some()).count();
        if available < self.data_shards {
            return Err(FecError::InsufficientShards {
                required: self.data_shards,
                available,
            });
        }

        // Reconstruct missing shards
        self.rs
            .reconstruct(&mut shards)
            .map_err(|e| FecError::DecodingFailed(e.to_string()))?;

        // Concatenate data shards
        let mut data = Vec::with_capacity(original_len);
        for shard in shards.into_iter().take(self.data_shards) {
            let s = shard.ok_or(FecError::DecodingFailed(
                "shard remained None after reconstruction".into(),
            ))?;
            data.extend_from_slice(&s);
        }

        // Trim to original length (remove padding)
        data.truncate(original_len);

        Ok(data)
    }

    /// Get the number of data shards
    pub fn data_shards(&self) -> usize {
        self.data_shards
    }

    /// Get the number of parity shards
    pub fn parity_shards(&self) -> usize {
        self.parity_shards
    }
}
