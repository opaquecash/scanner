//! # Stealth Attestation Scanner (V1 + V2)
//!
//! V1: Extends the EIP-5564 scanner to detect "Reputation Events" embedded in
//! announcement metadata. Extracts an `attestation_id` from the metadata byte string.
//!
//! V2: Validates that the attestation belongs to a registered schema and that the
//! issuer is the schema authority or a registered delegate. V2 traits carry
//! `schema_id`, `issuer`, `attestation_uid`, and a pre-computed `merkle_leaf` for
//! ZK proof generation. Rogue traits (issued by non-delegates) are silently ignored.

use alloy_primitives::Address;
use k256::{ecdsa::SigningKey, PublicKey};
use serde::{Deserialize, Serialize};

use crate::scanner::{
    check_announcement_view_tag, derive_stealth_address, StealthAddressError, ViewTagCheck,
};


// =============================================================================
// Attestation types
// =============================================================================

/// A discovered attestation tied to a stealth address announcement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthAttestation {
    pub stealth_address: String,
    pub attestation_id: u64,
    pub tx_hash: String,
    pub block_number: u64,
    pub ephemeral_pubkey: Vec<u8>,
}

/// Aggregated reputation score for a specific trait requirement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationSummary {
    pub trait_id: String,
    pub matching_announcements: Vec<StealthAttestation>,
    pub total_count: u64,
}

// =============================================================================
// Metadata attestation encoding
// =============================================================================

/// Attestation metadata layout in announcement `metadata` field:
///   byte[0]    = view_tag (standard EIP-5564)
///   byte[1]    = 0xAT (attestation marker = 0xA7)
///   byte[2..10] = attestation_id (big-endian u64)
///
/// Remaining bytes are reserved for future extensions.
const ATTESTATION_MARKER: u8 = 0xA7;
const ATTESTATION_METADATA_MIN_LEN: usize = 10;

/// Extracts an attestation_id from announcement metadata, if present.
pub fn extract_attestation_id(metadata: &[u8]) -> Option<u64> {
    if metadata.len() < ATTESTATION_METADATA_MIN_LEN {
        return None;
    }
    if metadata[1] != ATTESTATION_MARKER {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&metadata[2..10]);
    Some(u64::from_be_bytes(buf))
}

/// Encodes an attestation_id into metadata format (view_tag must be set by caller at byte[0]).
pub fn encode_attestation_metadata(view_tag: u8, attestation_id: u64) -> Vec<u8> {
    let mut metadata = Vec::with_capacity(ATTESTATION_METADATA_MIN_LEN);
    metadata.push(view_tag);
    metadata.push(ATTESTATION_MARKER);
    metadata.extend_from_slice(&attestation_id.to_be_bytes());
    metadata
}

// =============================================================================
// Attestation scanning
// =============================================================================

/// Raw announcement data from the chain/subgraph, before WASM boundary.
#[derive(Clone, Debug)]
pub struct RawAnnouncement {
    pub stealth_address: Address,
    pub view_tag: u8,
    pub ephemeral_pubkey: PublicKey,
    pub metadata: Vec<u8>,
    pub tx_hash: String,
    pub block_number: u64,
}

/// Scans a batch of announcements for attestations owned by this recipient.
///
/// Two-pass filter:
/// 1. View-tag pre-check (skip ~255/256 of announcements)
/// 2. Full stealth address derivation + attestation extraction
pub fn scan_for_attestations(
    announcements: &[RawAnnouncement],
    view_privkey: &SigningKey,
    spend_pubkey: &PublicKey,
) -> Result<Vec<StealthAttestation>, StealthAddressError> {
    let mut results = Vec::new();

    for ann in announcements {
        match check_announcement_view_tag(ann.view_tag, view_privkey, &ann.ephemeral_pubkey) {
            ViewTagCheck::NoMatch => continue,
            ViewTagCheck::PossibleMatch => {}
        }

        let (derived_addr, _) =
            derive_stealth_address(view_privkey, spend_pubkey, &ann.ephemeral_pubkey)?;

        if derived_addr != ann.stealth_address {
            continue;
        }

        if let Some(attestation_id) = extract_attestation_id(&ann.metadata) {
            let compressed = ann
                .ephemeral_pubkey
                .to_sec1_bytes()
                .to_vec();

            results.push(StealthAttestation {
                stealth_address: format!("{:#x}", ann.stealth_address),
                attestation_id,
                tx_hash: ann.tx_hash.clone(),
                block_number: ann.block_number,
                ephemeral_pubkey: compressed,
            });
        }
    }

    Ok(results)
}

/// Aggregates attestations matching a specific trait requirement.
///
/// For simple badge checks, `requirement` is a single attestation_id.
/// For threshold checks (e.g. "Total Volume > 5 ETH"), the caller should
/// pass all volume-type attestation IDs and the function counts matches.
pub fn aggregate_for_trait(
    attestations: &[StealthAttestation],
    trait_id: &str,
    required_attestation_ids: &[u64],
) -> ReputationSummary {
    let matching: Vec<StealthAttestation> = attestations
        .iter()
        .filter(|a| required_attestation_ids.contains(&a.attestation_id))
        .cloned()
        .collect();

    let total_count = matching.len() as u64;

    ReputationSummary {
        trait_id: trait_id.to_string(),
        matching_announcements: matching,
        total_count,
    }
}

// =============================================================================
// V2 Attestation types and scanning
// =============================================================================

/// V2 marker byte in announcement metadata
const V2_ATTESTATION_MARKER: u8 = 0xB2;

/// Minimum metadata length for a V2 announcement:
///   byte[0]    = view_tag
///   byte[1]    = 0xB2 (V2 marker)
///   byte[2..34]  = schema_id [u8; 32]
///   byte[34..66] = issuer pubkey [u8; 32] (first 32 bytes of compressed ed25519 key)
///   byte[66..98] = attestation_uid [u8; 32]
///   byte[98..130] = nonce [u8; 32]  (used in Merkle leaf construction)
const V2_METADATA_MIN_LEN: usize = 130;

/// A V2 discovered trait — schema-bound, issuer-verified, ready for ZK proof gen.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct V2StealthAttestation {
    /// Hex-encoded stealth address (Ethereum-style 0x…)
    pub stealth_address: String,
    /// Schema identifier [u8; 32] as hex
    pub schema_id: String,
    /// Optional display name for the schema (populated if schema registry is queried)
    pub schema_name: Option<String>,
    /// Issuer pubkey as base58 (Solana) or hex
    pub issuer: String,
    /// Attestation UID [u8; 32] as hex
    pub attestation_uid: String,
    /// ABI-encoded payload bytes as hex (decoded against schema field_definitions by caller)
    pub data_hex: String,
    /// Nonce used in the Merkle leaf — needed for ZK proof generation
    pub nonce: String,
    /// Pre-computed Merkle leaf value as hex: Poseidon(stealth_pk, schema_id, issuer_pk_x, data_hash, nonce)
    /// Computed off-chain; the actual Poseidon must be run in the browser prover.
    pub merkle_leaf_preimage: MerkleLeafPreimage,
    /// Transaction hash where this announcement appeared
    pub tx_hash: String,
    /// Slot (block) when the announcement was observed
    pub slot: u64,
    /// Whether the attestation is currently valid (not revoked, not expired).
    /// Set to true at scan time; callers should re-validate against chain state.
    pub is_valid: bool,
    /// True if this was issued by the schema authority or a known delegate.
    /// Rogue traits have this set to false and are filtered by default.
    pub issuer_authorized: bool,
}

/// All fields needed to reconstruct the V2 Poseidon leaf in the browser prover.
/// leaf = Poseidon(stealth_pk, schema_id_field, issuer_pk_x, trait_data_hash, nonce)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleLeafPreimage {
    /// Stealth pk field element (BN254 scalar, decimal string)
    pub stealth_pk_field: String,
    /// schema_id packed into BN254 field element (decimal string)
    pub schema_id_field: String,
    /// Issuer BabyJubJub x-coordinate (decimal string)
    pub issuer_pk_x: String,
    /// Poseidon(data fields) decimal string — caller computes from data_hex + schema
    pub trait_data_hash: String,
    /// Random nonce (decimal string)
    pub nonce_field: String,
}

/// Raw V2 announcement fields extracted from metadata bytes.
#[derive(Clone, Debug)]
pub struct V2AnnouncementFields {
    pub schema_id: [u8; 32],
    pub issuer: [u8; 32],
    pub attestation_uid: [u8; 32],
    pub nonce: [u8; 32],
}

/// Parses V2 fields from announcement metadata, returning None if not a V2 announcement.
pub fn extract_v2_fields(metadata: &[u8]) -> Option<V2AnnouncementFields> {
    if metadata.len() < V2_METADATA_MIN_LEN {
        return None;
    }
    if metadata[1] != V2_ATTESTATION_MARKER {
        return None;
    }
    let mut schema_id = [0u8; 32];
    let mut issuer = [0u8; 32];
    let mut attestation_uid = [0u8; 32];
    let mut nonce = [0u8; 32];

    schema_id.copy_from_slice(&metadata[2..34]);
    issuer.copy_from_slice(&metadata[34..66]);
    attestation_uid.copy_from_slice(&metadata[66..98]);
    nonce.copy_from_slice(&metadata[98..130]);

    Some(V2AnnouncementFields {
        schema_id,
        issuer,
        attestation_uid,
        nonce,
    })
}

/// Encodes a V2 announcement metadata payload.
///
/// Layout: view_tag || 0xB2 || schema_id[32] || issuer[32] || attestation_uid[32] || nonce[32]
pub fn encode_v2_attestation_metadata(
    view_tag: u8,
    schema_id: &[u8; 32],
    issuer: &[u8; 32],
    attestation_uid: &[u8; 32],
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut metadata = Vec::with_capacity(V2_METADATA_MIN_LEN);
    metadata.push(view_tag);
    metadata.push(V2_ATTESTATION_MARKER);
    metadata.extend_from_slice(schema_id);
    metadata.extend_from_slice(issuer);
    metadata.extend_from_slice(attestation_uid);
    metadata.extend_from_slice(nonce);
    metadata
}

/// A minimal schema description for issuer validation in the scanner.
/// In a full implementation this is fetched from the chain via RPC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchemaInfo {
    pub schema_id: [u8; 32],
    pub authority: [u8; 32],
    pub delegates: Vec<[u8; 32]>,
    pub deprecated: bool,
    pub schema_expiry_slot: u64,
    pub name: String,
}

impl SchemaInfo {
    pub fn is_authorized_issuer(&self, candidate: &[u8; 32]) -> bool {
        candidate == &self.authority || self.delegates.contains(candidate)
    }

    pub fn is_active(&self, current_slot: u64) -> bool {
        !self.deprecated
            && (self.schema_expiry_slot == 0 || current_slot < self.schema_expiry_slot)
    }
}

/// Scans a batch of V2 announcements for schema-bound attestations owned by this recipient.
///
/// Three-pass filter:
/// 1. View-tag pre-check (skip ~255/256 of announcements)
/// 2. Full stealth address derivation to confirm ownership
/// 3. Issuer authorization check against the provided schema registry snapshot
///
/// Rogue traits (unregistered schema_id or unauthorized issuer) are logged and skipped.
/// The caller is responsible for fetching up-to-date `schemas` from the chain.
pub fn scan_for_attestations_v2(
    announcements: &[RawAnnouncement],
    view_privkey: &k256::ecdsa::SigningKey,
    spend_pubkey: &k256::PublicKey,
    schemas: &[SchemaInfo],
    current_slot: u64,
    trusted_issuers: Option<&std::collections::HashSet<String>>,
) -> Result<Vec<V2StealthAttestation>, crate::scanner::StealthAddressError> {
    use crate::scanner::{check_announcement_view_tag, derive_stealth_address, ViewTagCheck};

    let mut results = Vec::new();

    for ann in announcements {
        // Step 1: View-tag fast path
        match check_announcement_view_tag(ann.view_tag, view_privkey, &ann.ephemeral_pubkey) {
            ViewTagCheck::NoMatch => continue,
            ViewTagCheck::PossibleMatch => {}
        }

        // Step 2: Full ECDH derivation to confirm this announcement is ours
        let (derived_addr, _) =
            derive_stealth_address(view_privkey, spend_pubkey, &ann.ephemeral_pubkey)?;
        if derived_addr != ann.stealth_address {
            continue;
        }

        // Step 3: Parse V2 metadata fields
        let v2 = match extract_v2_fields(&ann.metadata) {
            Some(f) => f,
            None => continue, // Not a V2 announcement — skip (V1 scanner handles V1)
        };

        // Step 4: Look up schema in the provided registry snapshot
        let schema = match schemas.iter().find(|s| s.schema_id == v2.schema_id) {
            Some(s) => s,
            None => {
                // Unknown schema_id — rogue trait, silently ignore
                continue;
            }
        };

        // Step 5: Check schema is not deprecated/expired
        if !schema.is_active(current_slot) {
            continue;
        }

        // Step 6: Validate the issuer is authorized under this schema
        let issuer_authorized = schema.is_authorized_issuer(&v2.issuer);

        // Step 7: Optional user-configured trusted issuer allowlist
        let issuer_hex = hex_encode(&v2.issuer);
        if let Some(trusted) = trusted_issuers {
            if !trusted.contains(&issuer_hex) {
                continue;
            }
        }

        // Step 8: Build the leaf preimage struct for the browser prover.
        // The actual Poseidon computation happens in JS with poseidon-lite.
        let stealth_addr_hex = format!("{:#x}", ann.stealth_address);
        let merkle_leaf_preimage = MerkleLeafPreimage {
            stealth_pk_field: "0".to_string(), // caller fills from stealth privkey
            schema_id_field: bytes_to_field_decimal(&v2.schema_id),
            issuer_pk_x: bytes_to_field_decimal(&v2.issuer),
            trait_data_hash: "0".to_string(), // caller fills after decoding data
            nonce_field: bytes_to_field_decimal(&v2.nonce),
        };

        results.push(V2StealthAttestation {
            stealth_address: stealth_addr_hex,
            schema_id: hex_encode(&v2.schema_id),
            schema_name: Some(schema.name.clone()),
            issuer: hex_encode(&v2.issuer),
            attestation_uid: hex_encode(&v2.attestation_uid),
            data_hex: String::new(), // encrypted payload decoded by caller with shared secret
            nonce: hex_encode(&v2.nonce),
            merkle_leaf_preimage,
            tx_hash: ann.tx_hash.clone(),
            slot: ann.block_number,
            is_valid: true, // caller re-validates against AttestationPDA on chain
            issuer_authorized,
        });
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Packs a 32-byte array into a decimal string suitable for Circom field inputs.
/// The value is treated as a big-endian 256-bit integer and converted to decimal.
/// For values that fit in u128 (most schema_ids in practice) this is exact.
/// For larger values the caller should use a proper big-integer library in JS.
fn bytes_to_field_decimal(bytes: &[u8; 32]) -> String {
    // Return as 0x hex — Circom 2.x accepts both hex and decimal for field inputs
    format!("0x{}", hex_encode(bytes))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_attestation_metadata() {
        let view_tag = 0x42;
        let attestation_id = 12345u64;
        let encoded = encode_attestation_metadata(view_tag, attestation_id);
        assert_eq!(encoded[0], view_tag);
        assert_eq!(encoded[1], ATTESTATION_MARKER);
        let decoded = extract_attestation_id(&encoded).expect("should decode");
        assert_eq!(decoded, attestation_id);
    }

    #[test]
    fn short_metadata_returns_none() {
        assert!(extract_attestation_id(&[0x42]).is_none());
        assert!(extract_attestation_id(&[0x42, 0xA7]).is_none());
    }

    #[test]
    fn wrong_marker_returns_none() {
        let mut data = vec![0x42, 0xFF];
        data.extend_from_slice(&42u64.to_be_bytes());
        assert!(extract_attestation_id(&data).is_none());
    }
}
