//! Solana adapter: decodes Anchor `Announcement` events from the `stealth-announcer`
//! program and `CrossChainAnnouncement` events from the `uab-receiver` program, and
//! (feature `native`) fetches them over JSON-RPC transaction logs.

use base64::Engine as _;

use super::uab_payload_to_announcement;
use crate::dksap::Announcement;

/// Wormhole chain id for Solana (mainnet-beta and devnet share id 1).
pub const WORMHOLE_CHAIN_SOLANA: u16 = 1;

/// Anchor event discriminator: `sha256("event:Announcement")[0..8]` (stealth-announcer).
pub const ANNOUNCEMENT_EVENT_DISCRIMINATOR: [u8; 8] = [7, 44, 132, 71, 104, 35, 168, 60];

/// Anchor event discriminator: `sha256("event:CrossChainAnnouncement")[0..8]` (uab-receiver).
pub const CROSS_CHAIN_ANNOUNCEMENT_EVENT_DISCRIMINATOR: [u8; 8] =
    [13, 87, 101, 171, 128, 65, 106, 220];

/// Base64-decode the payload of a `Program data: <base64>` log line, or `None` when
/// the line is some other log.
pub fn program_data_bytes(log_line: &str) -> Option<Vec<u8>> {
    let b64 = log_line.strip_prefix("Program data: ")?;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()
}

/// Borsh-style cursor over an Anchor event body.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], pos: usize) -> Self {
        Self { buf, pos }
    }

    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let out = self.buf.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(out)
    }

    fn read_u16_le(&mut self) -> Option<u16> {
        self.read_bytes(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u64_le(&mut self) -> Option<u64> {
        self.read_bytes(8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
    }

    fn read_vec_u8(&mut self) -> Option<&'a [u8]> {
        let len = self
            .read_bytes(4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)?;
        self.read_bytes(usize::try_from(len).ok()?)
    }
}

fn discriminator_matches(data: &[u8], discriminator: &[u8; 8]) -> bool {
    data.len() >= 8 && &data[..8] == discriminator
}

/// Decode a native `Announcement` event body (the bytes after base64-decoding a
/// `Program data:` line). Layout: `u64 scheme_id, vec<u8> stealth_address(20),
/// [32] caller, vec<u8> ephemeral_pubkey(33), vec<u8> metadata`. Returns `None`
/// for other events or malformed bodies.
pub fn decode_announcement_event(data: &[u8]) -> Option<Announcement> {
    if !discriminator_matches(data, &ANNOUNCEMENT_EVENT_DISCRIMINATOR) {
        return None;
    }
    let mut r = Reader::new(data, 8);
    let _scheme_id = r.read_u64_le()?;
    let stealth_address = r.read_vec_u8()?;
    let _caller = r.read_bytes(32)?;
    let ephemeral_pubkey = r.read_vec_u8()?;
    let metadata = r.read_vec_u8()?;
    if stealth_address.len() != 20 || ephemeral_pubkey.len() != 33 || metadata.is_empty() {
        return None;
    }
    Some(Announcement {
        stealth_address: format!("0x{}", hex::encode(stealth_address)),
        ephemeral_pubkey: ephemeral_pubkey.to_vec(),
        view_tag: metadata[0],
        metadata: metadata.to_vec(),
        chain_id: WORMHOLE_CHAIN_SOLANA,
    })
}

/// Decode a `CrossChainAnnouncement` event body from the `uab-receiver` program.
/// Layout: `u16 source_chain, [32] source_emitter, u64 sequence, vec<u8> payload(96)`.
/// The announcement keeps its ORIGIN `chain_id` from the payload (Ethereum = 2), so
/// relayed copies deduplicate against their native originals.
pub fn decode_cross_chain_event(data: &[u8]) -> Option<Announcement> {
    if !discriminator_matches(data, &CROSS_CHAIN_ANNOUNCEMENT_EVENT_DISCRIMINATOR) {
        return None;
    }
    let mut r = Reader::new(data, 8);
    let _source_chain = r.read_u16_le()?;
    let _source_emitter = r.read_bytes(32)?;
    let _sequence = r.read_u64_le()?;
    let payload = r.read_vec_u8()?;
    uab_payload_to_announcement(payload)
}

/// Decode every announcement (native or relayed) out of one transaction's log lines.
pub fn announcements_from_logs(log_lines: &[String]) -> Vec<Announcement> {
    let mut out = Vec::new();
    for line in log_lines {
        let Some(data) = program_data_bytes(line) else {
            continue;
        };
        if let Some(ann) = decode_announcement_event(&data) {
            out.push(ann);
        } else if let Some(ann) = decode_cross_chain_event(&data) {
            out.push(ann);
        }
    }
    out
}

#[cfg(feature = "native")]
pub use native::{SolanaAdapter, SolanaAdapterError};

#[cfg(feature = "native")]
mod native {
    use super::{announcements_from_logs, WORMHOLE_CHAIN_SOLANA};
    use crate::dksap::{Announcement, ChainAdapter};

    /// Errors from the JSON-RPC transport or response shape.
    #[derive(Debug)]
    pub enum SolanaAdapterError {
        /// Transport-level failure (connection, TLS, HTTP status).
        Http(String),
        /// The node answered with a JSON-RPC `error` object.
        Rpc(String),
        /// The response body did not have the expected shape.
        Decode(String),
    }

    /// [`ChainAdapter`] over Solana JSON-RPC: walks recent transactions of the
    /// `stealth-announcer` (and, when configured, the `uab-receiver`) program and
    /// decodes their Anchor events. The `cursor` is the minimum slot (inclusive);
    /// `limit` caps the signatures scanned per program.
    pub struct SolanaAdapter {
        rpc_url: String,
        announcer: String,
        uab_receiver: Option<String>,
        limit: usize,
    }

    impl SolanaAdapter {
        /// Adapter reading native announcements from the `announcer` program id.
        pub fn new(rpc_url: impl Into<String>, announcer: impl Into<String>) -> Self {
            Self {
                rpc_url: rpc_url.into(),
                announcer: announcer.into(),
                uab_receiver: None,
                limit: 1000,
            }
        }

        /// Also read relayed cross-chain announcements from this `uab-receiver` program.
        #[must_use]
        pub fn with_uab_receiver(mut self, uab_receiver: impl Into<String>) -> Self {
            self.uab_receiver = Some(uab_receiver.into());
            self
        }

        /// Cap the signatures scanned per program (default 1000).
        #[must_use]
        pub fn with_limit(mut self, limit: usize) -> Self {
            self.limit = limit;
            self
        }

        fn rpc(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, SolanaAdapterError> {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            });
            let response: serde_json::Value = ureq::post(&self.rpc_url)
                .send_json(body)
                .map_err(|e| SolanaAdapterError::Http(e.to_string()))?
                .into_json()
                .map_err(|e| SolanaAdapterError::Decode(e.to_string()))?;
            if let Some(err) = response.get("error") {
                return Err(SolanaAdapterError::Rpc(err.to_string()));
            }
            Ok(response.get("result").cloned().unwrap_or_default())
        }

        fn program_announcements(
            &self,
            program: &str,
            min_slot: u64,
        ) -> Result<Vec<Announcement>, SolanaAdapterError> {
            let signatures = self.rpc(
                "getSignaturesForAddress",
                serde_json::json!([program, { "limit": self.limit }]),
            )?;
            let entries = signatures
                .as_array()
                .ok_or_else(|| SolanaAdapterError::Decode("signatures not an array".into()))?;
            let mut out = Vec::new();
            for entry in entries {
                let slot = entry.get("slot").and_then(serde_json::Value::as_u64);
                if slot.is_some_and(|s| s < min_slot) || !entry["err"].is_null() {
                    continue;
                }
                let Some(signature) = entry.get("signature").and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let tx = self.rpc(
                    "getTransaction",
                    serde_json::json!([signature, {
                        "encoding": "json",
                        "commitment": "confirmed",
                        "maxSupportedTransactionVersion": 0,
                    }]),
                )?;
                let Some(log_lines) = tx
                    .get("meta")
                    .and_then(|m| m.get("logMessages"))
                    .and_then(serde_json::Value::as_array)
                else {
                    continue;
                };
                let lines: Vec<String> = log_lines
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect();
                out.extend(announcements_from_logs(&lines));
            }
            Ok(out)
        }
    }

    impl ChainAdapter for SolanaAdapter {
        type Error = SolanaAdapterError;

        fn chain_id(&self) -> u16 {
            WORMHOLE_CHAIN_SOLANA
        }

        fn name(&self) -> &str {
            "solana"
        }

        fn fetch_announcements(&self, cursor: u64) -> Result<Vec<Announcement>, Self::Error> {
            let mut out = self.program_announcements(&self.announcer, cursor)?;
            if let Some(receiver) = &self.uab_receiver {
                out.extend(self.program_announcements(receiver, cursor)?);
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_u8(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    fn native_event_bytes(stealth: &[u8], ephemeral: &[u8], metadata: &[u8]) -> Vec<u8> {
        let mut data = ANNOUNCEMENT_EVENT_DISCRIMINATOR.to_vec();
        data.extend_from_slice(&1u64.to_le_bytes()); // scheme id
        data.extend_from_slice(&vec_u8(stealth));
        data.extend_from_slice(&[0xcc; 32]); // caller
        data.extend_from_slice(&vec_u8(ephemeral));
        data.extend_from_slice(&vec_u8(metadata));
        data
    }

    #[test]
    fn decodes_native_announcement_event() {
        let stealth = [0xabu8; 20];
        let mut ephemeral = vec![0x02u8];
        ephemeral.extend_from_slice(&[0x11; 32]);
        let metadata = [0x7au8, 0x09];
        let data = native_event_bytes(&stealth, &ephemeral, &metadata);

        let ann = decode_announcement_event(&data).expect("decodes");
        assert_eq!(ann.stealth_address, format!("0x{}", "ab".repeat(20)));
        assert_eq!(ann.ephemeral_pubkey, ephemeral);
        assert_eq!(ann.view_tag, 0x7a);
        assert_eq!(ann.chain_id, WORMHOLE_CHAIN_SOLANA);

        // Wrong discriminator, truncated body, bad lengths.
        assert!(decode_announcement_event(&data[1..]).is_none());
        assert!(decode_announcement_event(&data[..20]).is_none());
        let bad = native_event_bytes(&[0xab; 19], &ephemeral, &metadata);
        assert!(decode_announcement_event(&bad).is_none());
    }

    #[test]
    fn decodes_cross_chain_event_via_uab_payload() {
        let mut payload = vec![0u8; 96];
        payload[0] = 0x55;
        payload[1] = 0x02;
        for b in &mut payload[46..66] {
            *b = 0xdd;
        }
        payload[67] = 2; // origin Ethereum
        let mut data = CROSS_CHAIN_ANNOUNCEMENT_EVENT_DISCRIMINATOR.to_vec();
        data.extend_from_slice(&2u16.to_le_bytes()); // source chain
        data.extend_from_slice(&[0xee; 32]); // emitter
        data.extend_from_slice(&7u64.to_le_bytes()); // sequence
        data.extend_from_slice(&vec_u8(&payload));

        let ann = decode_cross_chain_event(&data).expect("decodes");
        assert_eq!(ann.chain_id, 2, "origin chain id preserved");
        assert_eq!(ann.stealth_address, format!("0x{}", "dd".repeat(20)));
        assert_eq!(ann.view_tag, 0x55);

        // 95-byte payload rejected.
        let mut short = CROSS_CHAIN_ANNOUNCEMENT_EVENT_DISCRIMINATOR.to_vec();
        short.extend_from_slice(&2u16.to_le_bytes());
        short.extend_from_slice(&[0xee; 32]);
        short.extend_from_slice(&7u64.to_le_bytes());
        short.extend_from_slice(&vec_u8(&payload[..95]));
        assert!(decode_cross_chain_event(&short).is_none());
    }

    #[test]
    fn extracts_announcements_from_program_logs() {
        let stealth = [0x33u8; 20];
        let mut ephemeral = vec![0x03u8];
        ephemeral.extend_from_slice(&[0x44; 32]);
        let event = native_event_bytes(&stealth, &ephemeral, &[0x01]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&event);
        let logs = vec![
            "Program HGFn2fH7bVQ5cSuiG52NjzN9m11YrB3FZUfoN9b9A5jf invoke [1]".to_owned(),
            format!("Program data: {b64}"),
            "Program data: not-base64!!!".to_owned(),
            "Program HGFn2fH7bVQ5cSuiG52NjzN9m11YrB3FZUfoN9b9A5jf success".to_owned(),
        ];
        let anns = announcements_from_logs(&logs);
        assert_eq!(anns.len(), 1);
        assert_eq!(anns[0].stealth_address, format!("0x{}", "33".repeat(20)));
    }
}
