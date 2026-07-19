//! Starknet adapter: decodes `Announcement` events from the Cairo `stealth_announcer`
//! contract, and (feature `native`) fetches them over the `starknet_getEvents`
//! JSON-RPC endpoint.
//!
//! Mirrors the TypeScript `@opaquecash/stealth-chain-starknet` adapter. Starknet has
//! no UAB/Wormhole receiver (Wormhole does not support Starknet), so this adapter only
//! decodes NATIVE announcements — it participates in the unified inbox as a native scan
//! chain, not a relay endpoint.

use crate::dksap::Announcement;

/// Opaque-assigned chain id for Starknet ("SN"). Wormhole has no Starknet id; this
/// follows the CSAP §2.6 convention that gave Solana `0x534F` ("SO") and is far outside
/// Wormhole's registered range, so ids from the three chains never collide.
pub const OPAQUE_CHAIN_STARKNET: u16 = 0x534e;

/// `sn_keccak("Announcement")` — the event selector that is `keys[0]` of every
/// announcer event. Pinned from the live Sepolia event (verified on-chain).
pub const ANNOUNCEMENT_EVENT_SELECTOR: [u8; 32] =
    hex_literal_32("03b0aef39a70b56ef15742493d76e4564fece25d63e44474e1e3434aa467a374");

/// A Starknet field element as a 32-byte big-endian array.
pub type Felt = [u8; 32];

const fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Const hex → 32-byte big-endian (accepts up to 64 hex chars, right-aligned).
const fn hex_literal_32(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    // Consume hex-char pairs from the right so the string's last byte lands in out[31].
    let mut i = bytes.len();
    let mut out_idx = 32;
    while i >= 2 && out_idx >= 1 {
        out_idx -= 1;
        out[out_idx] = (hex_val(bytes[i - 2]) << 4) | hex_val(bytes[i - 1]);
        i -= 2;
    }
    // A single leftover nibble (odd-length input) is the low nibble of the next byte.
    if i == 1 && out_idx >= 1 {
        out[out_idx - 1] = hex_val(bytes[0]);
    }
    out
}

/// Parse a `0x`-prefixed (or bare) felt hex string into a 32-byte big-endian [`Felt`].
/// Returns `None` on invalid hex or an over-long value.
pub fn felt_from_hex(s: &str) -> Option<Felt> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.len() > 64 {
        return None;
    }
    let mut padded = String::with_capacity(64);
    for _ in 0..(64 - trimmed.len()) {
        padded.push('0');
    }
    padded.push_str(trimmed);
    let bytes = hex::decode(padded).ok()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn felt_to_u128_low(f: &Felt) -> u128 {
    let mut v = 0u128;
    for &b in &f[16..32] {
        v = (v << 8) | u128::from(b);
    }
    v
}

/// Decode one Cairo `ByteArray` from `felts` starting at `offset`. Serde layout:
/// `[num_full_words, ...full_words, pending_word, pending_len]`, where each full word
/// packs 31 big-endian bytes and the pending word holds `pending_len` (`< 31`) bytes.
/// Returns the bytes and how many felts were consumed.
pub fn decode_byte_array(felts: &[Felt], offset: usize) -> Option<(Vec<u8>, usize)> {
    let num_full_words = usize::try_from(felt_to_u128_low(felts.get(offset)?)).ok()?;
    let pending_idx = offset + 1 + num_full_words;
    let pending_len = usize::try_from(felt_to_u128_low(felts.get(pending_idx + 1)?)).ok()?;
    if pending_len >= 31 {
        return None;
    }
    let mut out = Vec::with_capacity(num_full_words * 31 + pending_len);
    for i in 0..num_full_words {
        let word = felts.get(offset + 1 + i)?;
        // A full word is < 2^248, so its 31 content bytes are the low 31 bytes.
        out.extend_from_slice(&word[1..32]);
    }
    let pending = felts.get(pending_idx)?;
    out.extend_from_slice(&pending[32 - pending_len..32]);
    Some((out, num_full_words + 3))
}

/// Decode a Starknet announcer event into the chain-neutral [`Announcement`].
///
/// `keys` = `[selector, scheme_id.low, scheme_id.high, stealth_address, caller]`;
/// `data` = `ByteArray ephemeral_pub_key` then `ByteArray metadata`. Returns `None`
/// for non-scheme-1 announcements or malformed bodies (skip, never panic — one bad
/// event must not kill a scan).
pub fn decode_announcement_event(keys: &[Felt], data: &[Felt]) -> Option<Announcement> {
    if keys.len() != 5 || keys[0] != ANNOUNCEMENT_EVENT_SELECTOR {
        return None;
    }
    // scheme_id (u256 low/high) must be 1.
    if felt_to_u128_low(&keys[1]) != 1 || felt_to_u128_low(&keys[2]) != 0 {
        return None;
    }
    let (ephemeral, consumed) = decode_byte_array(data, 0)?;
    let (metadata, _) = decode_byte_array(data, consumed)?;
    if ephemeral.len() != 33 || metadata.is_empty() {
        return None;
    }
    // stealth_address is a 20-byte EVM-style id in the low bytes of the felt.
    let stealth_address = format!("0x{}", hex::encode(&keys[3][12..32]));
    Some(Announcement {
        stealth_address,
        ephemeral_pubkey: ephemeral,
        view_tag: metadata[0],
        metadata,
        chain_id: OPAQUE_CHAIN_STARKNET,
    })
}

#[cfg(feature = "native")]
pub use native::{StarknetAdapter, StarknetAdapterError};

#[cfg(feature = "native")]
mod native {
    use super::{decode_announcement_event, felt_from_hex, ANNOUNCEMENT_EVENT_SELECTOR,
        OPAQUE_CHAIN_STARKNET};
    use crate::dksap::{Announcement, ChainAdapter};

    /// Errors from the JSON-RPC transport or response shape.
    #[derive(Debug)]
    pub enum StarknetAdapterError {
        /// Transport-level failure (connection, TLS, HTTP status).
        Http(String),
        /// The node answered with a JSON-RPC `error` object.
        Rpc(String),
        /// The response body did not have the expected shape.
        Decode(String),
    }

    /// [`ChainAdapter`] over Starknet JSON-RPC (spec 0.10.x): pages
    /// `starknet_getEvents` for the announcer contract and decodes each event. The
    /// `cursor` is the minimum block number (inclusive).
    pub struct StarknetAdapter {
        rpc_url: String,
        announcer: String,
        chunk_size: u64,
    }

    impl StarknetAdapter {
        /// Adapter reading announcements from the `announcer` contract address.
        pub fn new(rpc_url: impl Into<String>, announcer: impl Into<String>) -> Self {
            Self {
                rpc_url: rpc_url.into(),
                announcer: announcer.into(),
                chunk_size: 256,
            }
        }

        /// Events fetched per page (default 256).
        #[must_use]
        pub fn with_chunk_size(mut self, chunk_size: u64) -> Self {
            self.chunk_size = chunk_size;
            self
        }

        fn rpc(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, StarknetAdapterError> {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            });
            let response: serde_json::Value = ureq::post(&self.rpc_url)
                .send_json(body)
                .map_err(|e| StarknetAdapterError::Http(e.to_string()))?
                .into_json()
                .map_err(|e| StarknetAdapterError::Decode(e.to_string()))?;
            if let Some(err) = response.get("error") {
                return Err(StarknetAdapterError::Rpc(err.to_string()));
            }
            Ok(response.get("result").cloned().unwrap_or_default())
        }

        fn selector_hex() -> String {
            format!("0x{}", hex::encode(ANNOUNCEMENT_EVENT_SELECTOR))
        }
    }

    impl ChainAdapter for StarknetAdapter {
        type Error = StarknetAdapterError;

        fn chain_id(&self) -> u16 {
            OPAQUE_CHAIN_STARKNET
        }

        fn name(&self) -> &str {
            "starknet"
        }

        fn fetch_announcements(&self, cursor: u64) -> Result<Vec<Announcement>, Self::Error> {
            let mut out = Vec::new();
            let mut continuation: Option<String> = None;
            loop {
                let mut filter = serde_json::json!({
                    "address": self.announcer,
                    "keys": [[Self::selector_hex()]],
                    "from_block": { "block_number": cursor },
                    "to_block": "latest",
                    "chunk_size": self.chunk_size,
                });
                if let Some(token) = &continuation {
                    filter["continuation_token"] = serde_json::Value::String(token.clone());
                }
                let page = self.rpc("starknet_getEvents", serde_json::json!([filter]))?;
                let events = page
                    .get("events")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| StarknetAdapterError::Decode("events not an array".into()))?;
                for event in events {
                    let Some(ann) = decode_event_json(event) else {
                        continue;
                    };
                    out.push(ann);
                }
                match page.get("continuation_token").and_then(serde_json::Value::as_str) {
                    Some(token) => continuation = Some(token.to_owned()),
                    None => break,
                }
            }
            Ok(out)
        }
    }

    fn parse_felts(value: &serde_json::Value) -> Option<Vec<[u8; 32]>> {
        value
            .as_array()?
            .iter()
            .map(|v| v.as_str().and_then(felt_from_hex))
            .collect()
    }

    fn decode_event_json(event: &serde_json::Value) -> Option<Announcement> {
        let keys = parse_felts(event.get("keys")?)?;
        let data = parse_felts(event.get("data")?)?;
        decode_announcement_event(&keys, &data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The REAL Sepolia announcer event for CSAP canonical vector 1 (announced through
    /// the SDK call builder; tx 0x006efbb9…42d8, block 12158304). Decoding against
    /// on-chain truth, not our own encoder.
    fn live_event_keys() -> Vec<Felt> {
        [
            "0x3b0aef39a70b56ef15742493d76e4564fece25d63e44474e1e3434aa467a374",
            "0x1",
            "0x0",
            "0xa5847a467208cbcd5d238369865a90716310183a",
            "0x29db6e717afae61c5693afb65da25fb71974ccfe6705a8cc9282a8c9d725ceb",
        ]
        .iter()
        .map(|s| felt_from_hex(s).unwrap())
        .collect()
    }

    fn live_event_data() -> Vec<Felt> {
        [
            "0x1",
            "0x2b95c249d84f417e3e395a127425428b540671cc15881eb828c17b722a53f",
            "0xc599",
            "0x2",
            "0x0",
            "0xe1",
            "0x1",
        ]
        .iter()
        .map(|s| felt_from_hex(s).unwrap())
        .collect()
    }

    #[test]
    fn decodes_live_sepolia_announcement() {
        let ann = decode_announcement_event(&live_event_keys(), &live_event_data())
            .expect("decodes");
        assert_eq!(ann.stealth_address, "0xa5847a467208cbcd5d238369865a90716310183a");
        assert_eq!(
            hex::encode(&ann.ephemeral_pubkey),
            "02b95c249d84f417e3e395a127425428b540671cc15881eb828c17b722a53fc599"
        );
        assert_eq!(ann.ephemeral_pubkey.len(), 33);
        assert_eq!(ann.view_tag, 0xe1);
        assert_eq!(ann.metadata, vec![0xe1]);
        assert_eq!(ann.chain_id, OPAQUE_CHAIN_STARKNET);
    }

    #[test]
    fn byte_array_round_trips_across_word_boundaries() {
        for len in [0usize, 1, 30, 31, 32, 33, 62, 66, 98] {
            let bytes: Vec<u8> = (0..len).map(|i| ((i * 7 + 3) & 0xff) as u8).collect();
            let felts = encode_byte_array(&bytes);
            let (decoded, consumed) = decode_byte_array(&felts, 0).expect("decodes");
            assert_eq!(decoded, bytes, "len {len}");
            assert_eq!(consumed, felts.len(), "consumed all felts for len {len}");
        }
    }

    #[test]
    fn rejects_malformed_events() {
        // Wrong key count.
        assert!(decode_announcement_event(&live_event_keys()[..3], &live_event_data()).is_none());
        // scheme_id != 1.
        let mut keys = live_event_keys();
        keys[1] = felt_from_hex("0x2").unwrap();
        assert!(decode_announcement_event(&keys, &live_event_data()).is_none());
        // Truncated data.
        assert!(decode_announcement_event(&live_event_keys(), &live_event_data()[..2]).is_none());
        // Wrong selector.
        let mut wrong_sel = live_event_keys();
        wrong_sel[0] = felt_from_hex("0xdead").unwrap();
        assert!(decode_announcement_event(&wrong_sel, &live_event_data()).is_none());
    }

    /// Test-only ByteArray encoder mirroring the Cairo Serde layout.
    fn encode_byte_array(bytes: &[u8]) -> Vec<Felt> {
        let full_words = bytes.len() / 31;
        let mut felts = Vec::new();
        felts.push(u128_to_felt(full_words as u128));
        for i in 0..full_words {
            let mut word = [0u8; 32];
            word[1..32].copy_from_slice(&bytes[i * 31..(i + 1) * 31]);
            felts.push(word);
        }
        let pending = &bytes[full_words * 31..];
        let mut pending_felt = [0u8; 32];
        pending_felt[32 - pending.len()..32].copy_from_slice(pending);
        felts.push(pending_felt);
        felts.push(u128_to_felt(pending.len() as u128));
        felts
    }

    fn u128_to_felt(v: u128) -> Felt {
        let mut f = [0u8; 32];
        f[16..32].copy_from_slice(&v.to_be_bytes());
        f
    }

    #[test]
    fn felt_hex_parsing() {
        assert_eq!(felt_from_hex("0x1").unwrap()[31], 1);
        assert_eq!(felt_from_hex("0xff").unwrap()[31], 0xff);
        assert!(felt_from_hex("0xzz").is_none());
        assert!(felt_from_hex(&"f".repeat(65)).is_none());
    }
}
