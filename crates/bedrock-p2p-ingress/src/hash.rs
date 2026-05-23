use crate::error::{IngressError, Result};
use bedrock_forge::ZCASH_FULL_HEADER_SIZE;

pub fn display_hash_from_header(block_payload: &[u8]) -> Result<String> {
    let raw = raw_hash_from_header(block_payload)?;
    let mut display = raw;
    display.reverse();
    Ok(hex::encode(display))
}

pub fn raw_hash_from_header(block_payload: &[u8]) -> Result<[u8; 32]> {
    let header = block_payload
        .get(..ZCASH_FULL_HEADER_SIZE)
        .ok_or_else(|| IngressError::Wire("block payload shorter than Zcash header".to_string()))?;
    Ok(bedrock_forge::zcash_block_hash(header))
}

pub fn inventory_hash_to_display(hash: &[u8; 32]) -> String {
    let mut display = *hash;
    display.reverse();
    hex::encode(display)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_display_reverses_wire_hash() {
        let mut hash = [0u8; 32];
        hash[0] = 0x11;
        hash[31] = 0xff;
        let display = inventory_hash_to_display(&hash);
        assert!(display.starts_with("ff"));
        assert!(display.ends_with("11"));
    }

    #[test]
    fn rejects_short_block_payload() {
        assert!(raw_hash_from_header(&[0u8; 100]).is_err());
    }
}
