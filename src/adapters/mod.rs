//! Concrete [`ChainAdapter`](crate::dksap::ChainAdapter) implementations (guide Task 0.4).
//!
//! Event/log **decoders** are pure and always compiled (and unit-tested in plain
//! `cargo test`). The JSON-RPC **transports** need an HTTP client, so they are gated
//! behind the `native` cargo feature and excluded from the WASM build:
//!
//! ```toml
//! opaque-scanner = { version = "...", features = ["native"] }
//! ```

pub mod ethereum;
pub mod solana;
pub mod starknet;

use crate::dksap::Announcement;

/// Length of the fixed cross-chain announcement payload (`spec/payload-format.md`).
pub const UAB_PAYLOAD_LENGTH: usize = 96;

/// Decode the canonical 96-byte Universal Announcement Bus payload into the
/// chain-neutral [`Announcement`] shape. Mirrors `spec/payload-format.md`:
///
/// ```text
/// [0]      view_tag         (1)
/// [1..34)  ephemeral_pubkey (33)
/// [34..66) stealth_address  (32, left-padded; low 20 bytes = EVM-style address)
/// [66..68) source_chain_id  (2, big-endian Wormhole chain id)
/// [68..72) scheme_id        (4, big-endian)
/// [72..96) metadata         (24)
/// ```
///
/// The resulting `chain_id` is the announcement's ORIGIN chain, so relayed copies
/// deduplicate against their native originals. Scanner `metadata` is rebuilt as
/// `view_tag || tail` to match the EIP-5564 shape. Returns `None` on a wrong length.
pub fn uab_payload_to_announcement(payload: &[u8]) -> Option<Announcement> {
    if payload.len() != UAB_PAYLOAD_LENGTH {
        return None;
    }
    let view_tag = payload[0];
    let mut metadata = Vec::with_capacity(25);
    metadata.push(view_tag);
    metadata.extend_from_slice(&payload[72..96]);
    Some(Announcement {
        stealth_address: format!("0x{}", hex::encode(&payload[46..66])),
        ephemeral_pubkey: payload[1..34].to_vec(),
        view_tag,
        metadata,
        chain_id: u16::from_be_bytes([payload[66], payload[67]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uab_payload_round_trip() {
        let mut payload = vec![0u8; UAB_PAYLOAD_LENGTH];
        payload[0] = 0x7a; // view tag
        payload[1] = 0x02; // compressed-point prefix
        for (i, b) in payload.iter_mut().enumerate().take(34).skip(2) {
            *b = i as u8;
        }
        for (i, b) in payload.iter_mut().enumerate().take(66).skip(46) {
            *b = 0xa0 + (i as u8 - 46); // low 20 bytes of the stealth-address field
        }
        payload[66] = 0x00;
        payload[67] = 0x02; // origin = Ethereum
        payload[71] = 0x01; // scheme id 1
        payload[72] = 0xee; // metadata tail

        let ann = uab_payload_to_announcement(&payload).expect("valid payload");
        assert_eq!(ann.view_tag, 0x7a);
        assert_eq!(ann.ephemeral_pubkey.len(), 33);
        assert_eq!(ann.ephemeral_pubkey[0], 0x02);
        assert_eq!(ann.stealth_address.len(), 42);
        assert!(ann.stealth_address.starts_with("0xa0a1a2"));
        assert_eq!(ann.chain_id, 2);
        // metadata = view_tag || 24-byte tail
        assert_eq!(ann.metadata.len(), 25);
        assert_eq!(ann.metadata[0], 0x7a);
        assert_eq!(ann.metadata[1], 0xee);

        assert!(uab_payload_to_announcement(&payload[..95]).is_none());
    }
}
