use crate::error::{IngressError, Result};
use sovright_relay::ZCASH_FULL_HEADER_SIZE;

#[cfg(test)]
pub fn display_hash_from_header(block_payload: &[u8]) -> Result<String> {
    let raw = raw_hash_from_header(block_payload)?;
    let mut display = raw;
    display.reverse();
    Ok(hex::encode(display))
}

fn header(block_payload: &[u8]) -> Result<&[u8]> {
    block_payload
        .get(..ZCASH_FULL_HEADER_SIZE)
        .ok_or_else(|| IngressError::Wire("block payload shorter than Zcash header".to_string()))
}

/// The relay's internal object hash (BLAKE2b) of the block header. This is the
/// `hash` field of the ingress block events. It is NOT the hash peers use in
/// `inv`/`getdata`; match requests with [`inventory_hash_from_header`].
pub fn raw_hash_from_header(block_payload: &[u8]) -> Result<[u8; 32]> {
    Ok(sovright_relay::zcash_block_hash(header(block_payload)?))
}

/// The consensus block hash (double-SHA256 of the header) in wire byte order:
/// the hash a peer's `inv` announces and our `getdata` requests.
pub fn inventory_hash_from_header(block_payload: &[u8]) -> Result<[u8; 32]> {
    Ok(sovright_relay::consensus_block_hash(header(block_payload)?))
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
        assert!(inventory_hash_from_header(&[0u8; 100]).is_err());
    }

    #[test]
    fn inventory_hash_is_the_mainnet_consensus_hash() {
        use zcash_pool_common::fixtures::{
            MAINNET_BLOCK_3470793_HASH_DISPLAY, mainnet_serialized_header,
        };
        let inventory = inventory_hash_from_header(&mainnet_serialized_header()).unwrap();
        assert_eq!(
            inventory_hash_to_display(&inventory),
            MAINNET_BLOCK_3470793_HASH_DISPLAY
        );
    }
}
