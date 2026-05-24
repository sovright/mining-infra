use crate::v1::messages::{NotifyParams, SetDifficultyParams, SetTargetParams};
use std::fmt;
use zcash_mining_protocol::messages::{NewEquihashJob, SubmitEquihashShare};

#[derive(Debug, Clone)]
pub struct TranslateError(String);

impl TranslateError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for TranslateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TranslateError {}

pub fn hex_to_bytes(input: &str) -> Result<Vec<u8>, TranslateError> {
    let trimmed = input.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    if stripped.is_empty() {
        return Ok(Vec::new());
    }
    if !stripped.len().is_multiple_of(2) {
        return Err(TranslateError::new(format!(
            "hex string must contain an even number of digits: '{}'",
            input
        )));
    }

    let mut bytes = Vec::with_capacity(stripped.len() / 2);
    let chars: Vec<char> = stripped.chars().collect();
    for chunk in chars.chunks(2) {
        let high = decode_nibble(chunk[0])?;
        let low = decode_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }

    Ok(bytes)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
}

pub fn reverse_hash(hash: &[u8; 32]) -> [u8; 32] {
    let mut reversed = *hash;
    reversed.reverse();
    reversed
}

pub fn job_to_notify(job: &NewEquihashJob) -> NotifyParams {
    // version/ntime/nbits are sent as little-endian header bytes (the order
    // they appear in the serialized Zcash block header), matching the
    // real-world Zcash stratum dialect that ASIC firmware (e.g. Bitmain Z15 /
    // GodMiner) expects. Previously these were big-endian readable hex, which
    // Bedrock's own test miner tolerated but the Z15 rejected.
    NotifyParams(
        job.job_id.to_string(),
        bytes_to_hex(&job.version.to_le_bytes()),
        bytes_to_hex(&reverse_hash(&job.prev_hash)),
        bytes_to_hex(&reverse_hash(&job.merkle_root)),
        bytes_to_hex(&reverse_hash(&job.block_commitments)),
        bytes_to_hex(&job.time.to_le_bytes()),
        bytes_to_hex(&job.bits.to_le_bytes()),
        job.clean_jobs,
    )
}

pub fn target_to_v1(target: &[u8; 32]) -> (SetTargetParams, SetDifficultyParams) {
    let target_hex = bytes_to_hex(&reverse_hash(target));
    let difficulty = target_to_difficulty(target);
    (SetTargetParams(target_hex), SetDifficultyParams(difficulty))
}

pub fn submit_to_v2(
    channel_id: u32,
    sequence_number: u32,
    job_id: u32,
    nonce_2_hex: &str,
    time_hex: &str,
    solution_hex: &str,
) -> Result<SubmitEquihashShare, TranslateError> {
    let nonce_2 = hex_to_bytes(nonce_2_hex)?;
    let time = parse_hex_u32(time_hex)?;
    let solution = normalize_solution(solution_hex)?;

    Ok(SubmitEquihashShare {
        channel_id,
        sequence_number,
        job_id,
        nonce_2,
        time,
        solution,
    })
}

pub fn parse_hex_u32(input: &str) -> Result<u32, TranslateError> {
    let trimmed = input.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    if stripped.is_empty() {
        return Err(TranslateError::new("expected non-empty hex u32"));
    }
    if stripped.len() > 8 {
        return Err(TranslateError::new(format!(
            "hex value '{}' does not fit in u32",
            input
        )));
    }

    u32::from_str_radix(stripped, 16).map_err(|error| {
        TranslateError::new(format!("invalid u32 hex '{}': {}", input, error))
    })
}

pub fn normalize_solution(solution_hex: &str) -> Result<[u8; 1344], TranslateError> {
    let bytes = hex_to_bytes(solution_hex)?;
    let slice = match bytes.as_slice() {
        raw if raw.len() == SubmitEquihashShare::SOLUTION_SIZE => raw,
        prefixed if prefixed.len() == SubmitEquihashShare::SOLUTION_SIZE + 3
            && prefixed.starts_with(&[0xfd, 0x40, 0x05]) =>
        {
            &prefixed[3..]
        }
        other => {
            return Err(TranslateError::new(format!(
                "solution must be 1344 bytes raw or 1347 bytes with compactSize prefix, got {} bytes",
                other.len()
            )));
        }
    };

    let mut solution = [0u8; SubmitEquihashShare::SOLUTION_SIZE];
    solution.copy_from_slice(slice);
    Ok(solution)
}

pub fn target_to_difficulty(target: &[u8; 32]) -> f64 {
    let target_value = target_bytes_to_f64(target);
    if target_value == 0.0 {
        return f64::INFINITY;
    }
    target_bytes_to_f64(&max_mainnet_target()) / target_value
}

#[allow(dead_code)]
pub fn difficulty_to_target(difficulty: f64) -> [u8; 32] {
    if !difficulty.is_finite() || difficulty <= 0.0 {
        return max_mainnet_target();
    }
    if difficulty < 1.0 {
        return [0xff; 32];
    }

    f64_to_target_bytes(target_bytes_to_f64(&max_mainnet_target()) / difficulty)
}

fn decode_nibble(input: char) -> Result<u8, TranslateError> {
    match input {
        '0'..='9' => Ok(input as u8 - b'0'),
        'a'..='f' => Ok(input as u8 - b'a' + 10),
        'A'..='F' => Ok(input as u8 - b'A' + 10),
        _ => Err(TranslateError::new(format!(
            "invalid hex character '{}'",
            input
        ))),
    }
}

fn max_mainnet_target() -> [u8; 32] {
    let mut target = [0xff; 32];
    target[28] = 0x07;
    target[29] = 0x00;
    target[30] = 0x00;
    target[31] = 0x00;
    target
}

fn target_bytes_to_f64(target: &[u8; 32]) -> f64 {
    let mut value = 0.0f64;
    for byte in target.iter().rev() {
        value = value * 256.0 + f64::from(*byte);
    }
    value
}

fn f64_to_target_bytes(mut value: f64) -> [u8; 32] {
    let mut target = [0u8; 32];
    for byte in &mut target {
        let next = (value % 256.0) as u8;
        *byte = next;
        value = (value - f64::from(next)) / 256.0;
    }
    target
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_with_prefix_and_case() {
        assert_eq!(hex_to_bytes("0xAaFF").unwrap(), vec![0xaa, 0xff]);
    }

    #[test]
    fn strip_compact_size_solution_prefix() {
        let mut prefixed = vec![0xfd, 0x40, 0x05];
        prefixed.extend(std::iter::repeat_n(0xab, 1344));
        let solution = normalize_solution(&bytes_to_hex(&prefixed)).unwrap();
        assert_eq!(solution, [0xab; 1344]);
    }

    #[test]
    fn difficulty_roundtrip_is_reasonable() {
        let values = [1.0, 16.0, 1024.0, 1_000_000.0];
        for difficulty in values {
            let target = difficulty_to_target(difficulty);
            let recovered = target_to_difficulty(&target);
            let ratio = recovered / difficulty;
            assert!(ratio > 0.99 && ratio < 1.01);
        }
    }
}
