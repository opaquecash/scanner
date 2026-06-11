//! Ethereum adapter: decodes `StealthAddressAnnouncer.Announcement` and
//! `UABReceiver.CrossChainAnnouncement` logs, and (feature `native`) fetches them
//! over JSON-RPC `eth_getLogs`.

use serde::Deserialize;
use sha3::{Digest, Keccak256};

use super::uab_payload_to_announcement;
use crate::dksap::Announcement;

/// Wormhole chain id for Ethereum (mainnet and testnets share id 2).
pub const WORMHOLE_CHAIN_ETHEREUM: u16 = 2;

/// Minimal `eth_getLogs` result entry — only what the decoders need.
#[derive(Clone, Debug, Deserialize)]
pub struct EthLog {
    pub topics: Vec<String>,
    pub data: String,
}

/// `topic0` of `Announcement(uint256,address,address,bytes,bytes)` as `0x`-hex.
pub fn announcement_topic0() -> String {
    topic0("Announcement(uint256,address,address,bytes,bytes)")
}

/// `topic0` of `CrossChainAnnouncement(uint16,bytes32,uint64,bytes)` as `0x`-hex.
pub fn cross_chain_announcement_topic0() -> String {
    topic0("CrossChainAnnouncement(uint16,bytes32,uint64,bytes)")
}

fn topic0(signature: &str) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(signature.as_bytes())))
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok()
}

/// Read the dynamic `bytes` value referenced by head word `head_index` of ABI `data`.
fn abi_dynamic_bytes(data: &[u8], head_index: usize) -> Option<Vec<u8>> {
    let head = data.get(head_index * 32..head_index * 32 + 32)?;
    let offset = usize::try_from(u64::from_be_bytes(head[24..32].try_into().ok()?)).ok()?;
    let len_word = data.get(offset..offset + 32)?;
    let len = usize::try_from(u64::from_be_bytes(len_word[24..32].try_into().ok()?)).ok()?;
    data.get(offset + 32..offset + 32 + len).map(<[u8]>::to_vec)
}

/// Decode an `Announcement` log (ERC-5564 shape: scheme id, stealth address, and
/// caller indexed; ephemeral key + metadata in `data`). Returns `None` when the log
/// is not a well-formed announcement (wrong topic0, malformed ABI, non-33-byte
/// ephemeral key, or empty metadata).
pub fn decode_announcement_log(log: &EthLog) -> Option<Announcement> {
    if log.topics.len() != 4 || !log.topics[0].eq_ignore_ascii_case(&announcement_topic0()) {
        return None;
    }
    let stealth_topic = hex_bytes(&log.topics[2])?;
    if stealth_topic.len() != 32 {
        return None;
    }
    let data = hex_bytes(&log.data)?;
    let ephemeral_pubkey = abi_dynamic_bytes(&data, 0)?;
    let metadata = abi_dynamic_bytes(&data, 1)?;
    if ephemeral_pubkey.len() != 33 || metadata.is_empty() {
        return None;
    }
    Some(Announcement {
        stealth_address: format!("0x{}", hex::encode(&stealth_topic[12..32])),
        ephemeral_pubkey,
        view_tag: metadata[0],
        metadata,
        chain_id: WORMHOLE_CHAIN_ETHEREUM,
    })
}

/// Decode a `CrossChainAnnouncement` log re-emitted by the `UABReceiver` (source
/// chain + emitter indexed; sequence + 96-byte payload in `data`). The announcement
/// keeps its ORIGIN `chain_id` from the payload, so it deduplicates against the
/// native original.
pub fn decode_cross_chain_log(log: &EthLog) -> Option<Announcement> {
    if log.topics.len() != 3
        || !log.topics[0].eq_ignore_ascii_case(&cross_chain_announcement_topic0())
    {
        return None;
    }
    let data = hex_bytes(&log.data)?;
    // Head: word 0 = uint64 sequence, word 1 = offset to the dynamic payload.
    let payload = abi_dynamic_bytes(&data, 1)?;
    uab_payload_to_announcement(&payload)
}

#[cfg(feature = "native")]
pub use native::{EthereumAdapter, EthereumAdapterError};

#[cfg(feature = "native")]
mod native {
    use super::{
        announcement_topic0, cross_chain_announcement_topic0, decode_announcement_log,
        decode_cross_chain_log, EthLog, WORMHOLE_CHAIN_ETHEREUM,
    };
    use crate::dksap::{Announcement, ChainAdapter};

    /// Errors from the JSON-RPC transport or response shape.
    #[derive(Debug)]
    pub enum EthereumAdapterError {
        /// Transport-level failure (connection, TLS, HTTP status).
        Http(String),
        /// The node answered with a JSON-RPC `error` object.
        Rpc(String),
        /// The response body did not have the expected shape.
        Decode(String),
    }

    /// [`ChainAdapter`] over `eth_getLogs`: native `Announcement` logs from the
    /// announcer, plus (when configured) `CrossChainAnnouncement` logs from the
    /// UAB receiver. The `cursor` is the inclusive `fromBlock`.
    pub struct EthereumAdapter {
        rpc_url: String,
        announcer: String,
        uab_receiver: Option<String>,
    }

    impl EthereumAdapter {
        /// Adapter reading native announcements from `announcer` via `rpc_url`.
        pub fn new(rpc_url: impl Into<String>, announcer: impl Into<String>) -> Self {
            Self {
                rpc_url: rpc_url.into(),
                announcer: announcer.into(),
                uab_receiver: None,
            }
        }

        /// Also read relayed cross-chain announcements from this `UABReceiver`.
        #[must_use]
        pub fn with_uab_receiver(mut self, uab_receiver: impl Into<String>) -> Self {
            self.uab_receiver = Some(uab_receiver.into());
            self
        }

        fn get_logs(
            &self,
            address: &str,
            topic0: &str,
            from_block: u64,
        ) -> Result<Vec<EthLog>, EthereumAdapterError> {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_getLogs",
                "params": [{
                    "address": address,
                    "fromBlock": format!("0x{from_block:x}"),
                    "toBlock": "latest",
                    "topics": [topic0],
                }],
            });
            let response: serde_json::Value = ureq::post(&self.rpc_url)
                .send_json(body)
                .map_err(|e| EthereumAdapterError::Http(e.to_string()))?
                .into_json()
                .map_err(|e| EthereumAdapterError::Decode(e.to_string()))?;
            if let Some(err) = response.get("error") {
                return Err(EthereumAdapterError::Rpc(err.to_string()));
            }
            serde_json::from_value(response.get("result").cloned().unwrap_or_default())
                .map_err(|e| EthereumAdapterError::Decode(e.to_string()))
        }
    }

    impl ChainAdapter for EthereumAdapter {
        type Error = EthereumAdapterError;

        fn chain_id(&self) -> u16 {
            WORMHOLE_CHAIN_ETHEREUM
        }

        fn name(&self) -> &str {
            "ethereum"
        }

        fn fetch_announcements(&self, cursor: u64) -> Result<Vec<Announcement>, Self::Error> {
            let mut out = Vec::new();
            for log in self.get_logs(&self.announcer, &announcement_topic0(), cursor)? {
                if let Some(ann) = decode_announcement_log(&log) {
                    out.push(ann);
                }
            }
            if let Some(receiver) = &self.uab_receiver {
                for log in self.get_logs(receiver, &cross_chain_announcement_topic0(), cursor)? {
                    if let Some(ann) = decode_cross_chain_log(&log) {
                        out.push(ann);
                    }
                }
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abi_two_bytes(first: &[u8], second: &[u8]) -> String {
        // Standard ABI encoding of (bytes, bytes): two offset words, then each
        // value as a length word + right-padded payload.
        let mut data = Vec::new();
        let pad = |len: usize| len.div_ceil(32) * 32;
        let first_offset = 64usize;
        let second_offset = first_offset + 32 + pad(first.len());
        for offset in [first_offset, second_offset] {
            let mut word = [0u8; 32];
            word[24..32].copy_from_slice(&(offset as u64).to_be_bytes());
            data.extend_from_slice(&word);
        }
        for value in [first, second] {
            let mut len_word = [0u8; 32];
            len_word[24..32].copy_from_slice(&(value.len() as u64).to_be_bytes());
            data.extend_from_slice(&len_word);
            data.extend_from_slice(value);
            data.resize(data.len() + (pad(value.len()) - value.len()), 0);
        }
        format!("0x{}", hex::encode(data))
    }

    fn address_topic(addr_byte: u8) -> String {
        let mut topic = [0u8; 32];
        for b in &mut topic[12..32] {
            *b = addr_byte;
        }
        format!("0x{}", hex::encode(topic))
    }

    #[test]
    fn decodes_native_announcement_log() {
        let ephemeral = {
            let mut e = vec![0x02u8];
            e.extend_from_slice(&[0x11; 32]);
            e
        };
        let metadata = vec![0x7au8, 0x01, 0x02];
        let log = EthLog {
            topics: vec![
                announcement_topic0(),
                format!("0x{}", hex::encode([0u8; 32])), // schemeId
                address_topic(0xab),
                address_topic(0xcd), // caller
            ],
            data: abi_two_bytes(&ephemeral, &metadata),
        };
        let ann = decode_announcement_log(&log).expect("decodes");
        assert_eq!(ann.stealth_address, format!("0x{}", "ab".repeat(20)));
        assert_eq!(ann.ephemeral_pubkey, ephemeral);
        assert_eq!(ann.view_tag, 0x7a);
        assert_eq!(ann.metadata, metadata);
        assert_eq!(ann.chain_id, WORMHOLE_CHAIN_ETHEREUM);
    }

    #[test]
    fn rejects_malformed_announcement_logs() {
        let good_eph = {
            let mut e = vec![0x02u8];
            e.extend_from_slice(&[0x11; 32]);
            e
        };
        // Wrong topic0.
        let mut log = EthLog {
            topics: vec![
                cross_chain_announcement_topic0(),
                address_topic(0),
                address_topic(0xab),
                address_topic(0xcd),
            ],
            data: abi_two_bytes(&good_eph, &[0x7a]),
        };
        assert!(decode_announcement_log(&log).is_none());
        // 32-byte ephemeral key (not a compressed point length).
        log.topics[0] = announcement_topic0();
        log.data = abi_two_bytes(&[0x22; 32], &[0x7a]);
        assert!(decode_announcement_log(&log).is_none());
        // Empty metadata (no view tag).
        log.data = abi_two_bytes(&good_eph, &[]);
        assert!(decode_announcement_log(&log).is_none());
        // Truncated ABI data.
        log.data = "0x1234".into();
        assert!(decode_announcement_log(&log).is_none());
    }

    #[test]
    fn decodes_cross_chain_log_with_origin_chain_id() {
        let mut payload = vec![0u8; 96];
        payload[0] = 0x42;
        payload[1] = 0x03;
        for b in &mut payload[46..66] {
            *b = 0xee;
        }
        payload[67] = 1; // origin = Solana
        payload[71] = 1; // scheme 1
        let mut data = Vec::new();
        let mut seq_word = [0u8; 32];
        seq_word[31] = 9; // sequence
        data.extend_from_slice(&seq_word);
        let mut offset_word = [0u8; 32];
        offset_word[31] = 64;
        data.extend_from_slice(&offset_word);
        let mut len_word = [0u8; 32];
        len_word[31] = 96;
        data.extend_from_slice(&len_word);
        data.extend_from_slice(&payload);
        let log = EthLog {
            topics: vec![
                cross_chain_announcement_topic0(),
                format!("0x{}", hex::encode([0u8; 32])),
                format!("0x{}", hex::encode([1u8; 32])),
            ],
            data: format!("0x{}", hex::encode(data)),
        };
        let ann = decode_cross_chain_log(&log).expect("decodes");
        assert_eq!(ann.chain_id, 1, "origin chain id, not the local chain");
        assert_eq!(ann.stealth_address, format!("0x{}", "ee".repeat(20)));
        assert_eq!(ann.view_tag, 0x42);
    }
}
