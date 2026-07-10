//! # Opaque Cash — WASM Bindings
//!
//! WebAssembly bindings for the stealth address scanner engine (EIP-5564 / DKSAP).

use wasm_bindgen::prelude::*;
use k256::{ecdsa::SigningKey, PublicKey};
use alloy_primitives::Address;
use std::str::FromStr;

pub mod scanner;
pub mod attestation;
pub mod merkle;
pub mod dksap;
pub mod adapters;
pub mod universal;

use scanner::{
    derive_stealth_address, derive_stealth_signing_key, check_announcement,
    check_announcement_view_tag, ViewTagCheck,
};

// Initialize panic hook for better error messages in browser console
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// =============================================================================
// Type conversions: Rust <-> JavaScript
// =============================================================================

/// Converts a 32-byte Uint8Array to a SigningKey
fn bytes_to_signing_key(bytes: &[u8]) -> Result<SigningKey, JsValue> {
    if bytes.len() != 32 {
        return Err(JsValue::from_str("SigningKey must be 32 bytes"));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(bytes);
    SigningKey::from_bytes(&key_bytes.into())
        .map_err(|e| JsValue::from_str(&format!("Invalid signing key: {}", e)))
}

/// Converts a compressed public key (33 bytes) to PublicKey
fn bytes_to_public_key(bytes: &[u8]) -> Result<PublicKey, JsValue> {
    if bytes.len() != 33 {
        return Err(JsValue::from_str("PublicKey must be 33 bytes (compressed)"));
    }
    PublicKey::from_sec1_bytes(bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {}", e)))
}

/// Converts an Address to a hex string
fn address_to_hex(address: &Address) -> String {
    format!("{:#x}", address)
}

/// Converts a hex string to an Address
fn hex_to_address(hex: &str) -> Result<Address, JsValue> {
    Address::from_str(hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid address hex: {}", e)))
}

// =============================================================================
// WASM Exports
// =============================================================================

/// Derives a stealth address and view tag from the given keys.
///
/// # Arguments
/// * `view_privkey_bytes` - 32-byte viewing private key (Uint8Array)
/// * `spend_pubkey_bytes` - 33-byte spending public key, compressed (Uint8Array)
/// * `ephemeral_pubkey_bytes` - 33-byte ephemeral public key, compressed (Uint8Array)
///
/// # Returns
/// A JavaScript object with:
/// * `stealthAddress` - Ethereum address as hex string (0x...)
/// * `viewTag` - View tag as number (0-255)
#[wasm_bindgen]
pub fn derive_stealth_address_wasm(
    view_privkey_bytes: &[u8],
    spend_pubkey_bytes: &[u8],
    ephemeral_pubkey_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    let view_privkey = bytes_to_signing_key(view_privkey_bytes)?;
    let spend_pubkey = bytes_to_public_key(spend_pubkey_bytes)?;
    let ephemeral_pubkey = bytes_to_public_key(ephemeral_pubkey_bytes)?;

    match derive_stealth_address(&view_privkey, &spend_pubkey, &ephemeral_pubkey) {
        Ok((address, view_tag)) => {
            let result = js_sys::Object::new();
            js_sys::Reflect::set(
                &result,
                &"stealthAddress".into(),
                &address_to_hex(&address).into(),
            )?;
            js_sys::Reflect::set(
                &result,
                &"viewTag".into(),
                &JsValue::from(view_tag as u32),
            )?;
            Ok(result.into())
        }
        Err(e) => Err(JsValue::from_str(&format!("Stealth address error: {}", e))),
    }
}

/// Checks if an announcement matches this recipient's keys.
///
/// # Arguments
/// * `announcement_stealth_address` - Stealth address from announcement (hex string)
/// * `view_tag` - View tag from announcement (number 0-255)
/// * `view_privkey_bytes` - 32-byte viewing private key (Uint8Array)
/// * `spend_pubkey_bytes` - 33-byte spending public key, compressed (Uint8Array)
/// * `ephemeral_pubkey_bytes` - 33-byte ephemeral public key, compressed (Uint8Array)
///
/// # Returns
/// `true` if the announcement is for this recipient, `false` otherwise.
#[wasm_bindgen]
pub fn check_announcement_wasm(
    announcement_stealth_address: &str,
    view_tag: u8,
    view_privkey_bytes: &[u8],
    spend_pubkey_bytes: &[u8],
    ephemeral_pubkey_bytes: &[u8],
) -> Result<bool, JsValue> {
    let address = hex_to_address(announcement_stealth_address)?;
    let view_privkey = bytes_to_signing_key(view_privkey_bytes)?;
    let spend_pubkey = bytes_to_public_key(spend_pubkey_bytes)?;
    let ephemeral_pubkey = bytes_to_public_key(ephemeral_pubkey_bytes)?;

    check_announcement(
        address,
        view_tag,
        &view_privkey,
        &spend_pubkey,
        &ephemeral_pubkey,
    )
    .map_err(|e| JsValue::from_str(&format!("Check announcement error: {}", e)))
}

/// Quick view-tag check before expensive EC operations.
///
/// # Arguments
/// * `view_tag` - View tag from announcement (number 0-255)
/// * `view_privkey_bytes` - 32-byte viewing private key (Uint8Array)
/// * `ephemeral_pubkey_bytes` - 33-byte ephemeral public key, compressed (Uint8Array)
///
/// # Returns
/// `"NoMatch"` if view tag doesn't match (skip this announcement),
/// `"PossibleMatch"` if view tag matches (proceed with full check).
#[wasm_bindgen]
pub fn check_announcement_view_tag_wasm(
    view_tag: u8,
    view_privkey_bytes: &[u8],
    ephemeral_pubkey_bytes: &[u8],
) -> Result<String, JsValue> {
    let view_privkey = bytes_to_signing_key(view_privkey_bytes)?;
    let ephemeral_pubkey = bytes_to_public_key(ephemeral_pubkey_bytes)?;

    match check_announcement_view_tag(view_tag, &view_privkey, &ephemeral_pubkey) {
        ViewTagCheck::NoMatch => Ok("NoMatch".to_string()),
        ViewTagCheck::PossibleMatch => Ok("PossibleMatch".to_string()),
    }
}

/// Reconstructs the one-time signing key (private key) for a stealth address.
///
/// # Arguments
/// * `master_spend_priv_bytes` - 32-byte spending private key (Uint8Array)
/// * `master_view_priv_bytes` - 32-byte viewing private key (Uint8Array)
/// * `ephemeral_pubkey_bytes` - 33-byte ephemeral public key, compressed (Uint8Array)
///
/// # Returns
/// 32-byte stealth private key as Uint8Array (for use with ethers.Wallet or viem privateKeyToAccount).
#[wasm_bindgen]
pub fn reconstruct_signing_key_wasm(
    master_spend_priv_bytes: &[u8],
    master_view_priv_bytes: &[u8],
    ephemeral_pubkey_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let spend_privkey = bytes_to_signing_key(master_spend_priv_bytes)?;
    let view_privkey = bytes_to_signing_key(master_view_priv_bytes)?;
    let ephemeral_pubkey = bytes_to_public_key(ephemeral_pubkey_bytes)?;

    derive_stealth_signing_key(&view_privkey, &spend_privkey, &ephemeral_pubkey)
        .map(|bytes| bytes.to_vec())
        .map_err(|e| JsValue::from_str(&format!("Reconstruct signing key error: {}", e)))
}

// =============================================================================
// Stealth Attestation — WASM Exports
// =============================================================================

use attestation::{
    scan_for_attestations,
    scan_for_attestations_v2,
    RawAnnouncement, SchemaInfo,
};

/// Scans announcement metadata for attestation markers.
///
/// # Arguments
/// * `announcements_json` - JSON array of announcements, each with:
///   `{ stealthAddress, viewTag, ephemeralPubKey, metadata, txHash, blockNumber }`
/// * `view_privkey_bytes` - 32-byte viewing private key
/// * `spend_pubkey_bytes` - 33-byte spending public key (compressed)
///
/// # Returns
/// JSON array of `StealthAttestation` objects found for this recipient.
#[wasm_bindgen]
pub fn scan_attestations_wasm(
    announcements_json: &str,
    view_privkey_bytes: &[u8],
    spend_pubkey_bytes: &[u8],
) -> Result<String, JsValue> {
    let view_privkey = bytes_to_signing_key(view_privkey_bytes)?;
    let spend_pubkey = bytes_to_public_key(spend_pubkey_bytes)?;

    let raw_anns: Vec<serde_json::Value> = serde_json::from_str(announcements_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid JSON: {}", e)))?;

    let mut announcements = Vec::with_capacity(raw_anns.len());
    for ann in &raw_anns {
        let stealth_addr_str = ann["stealthAddress"].as_str().unwrap_or_default();
        let stealth_address = hex_to_address(stealth_addr_str)?;
        let view_tag = ann["viewTag"].as_u64().unwrap_or(0) as u8;

        let eph_hex = ann["ephemeralPubKey"].as_str().unwrap_or_default();
        let eph_clean = eph_hex.strip_prefix("0x").unwrap_or(eph_hex);
        let eph_bytes = hex::decode(eph_clean)
            .map_err(|e| JsValue::from_str(&format!("Invalid ephemeral pubkey hex: {}", e)))?;
        let ephemeral_pubkey = bytes_to_public_key(&eph_bytes)?;

        let meta_hex = ann["metadata"].as_str().unwrap_or_default();
        let meta_clean = meta_hex.strip_prefix("0x").unwrap_or(meta_hex);
        let metadata = hex::decode(meta_clean).unwrap_or_default();

        let tx_hash = ann["txHash"].as_str().unwrap_or_default().to_string();
        let block_number = ann["blockNumber"].as_u64().unwrap_or(0);

        announcements.push(RawAnnouncement {
            stealth_address,
            view_tag,
            ephemeral_pubkey,
            metadata,
            tx_hash,
            block_number,
        });
    }

    let results = scan_for_attestations(&announcements, &view_privkey, &spend_pubkey)
        .map_err(|e| JsValue::from_str(&format!("Scan error: {}", e)))?;

    serde_json::to_string(&results)
        .map_err(|e| JsValue::from_str(&format!("Serialize error: {}", e)))
}

/// Encodes attestation metadata for use in announcements.
///
/// # Arguments
/// * `view_tag` - View tag byte (0-255)
/// * `attestation_id` - Attestation/badge ID
///
/// # Returns
/// Hex-encoded metadata bytes.
#[wasm_bindgen]
pub fn encode_attestation_metadata_wasm(view_tag: u8, attestation_id: u64) -> String {
    let metadata = attestation::encode_attestation_metadata(view_tag, attestation_id);
    format!("0x{}", metadata.iter().map(|b| format!("{:02x}", b)).collect::<String>())
}

// =============================================================================
// V2 WASM Exports
// =============================================================================

/// Encodes V2 attestation metadata for use in stealth announcements.
///
/// Layout: view_tag(1) || 0xB2(1) || schema_id(32) || issuer(32) || attestation_uid(32) || nonce(32)
///
/// # Arguments
/// * `view_tag` - View tag byte (0-255)
/// * `schema_id_hex` - Schema identifier as 64-char hex string (32 bytes)
/// * `issuer_hex` - Issuer pubkey as 64-char hex string (32 bytes)
/// * `attestation_uid_hex` - Attestation UID as 64-char hex string (32 bytes)
/// * `nonce_hex` - Random nonce as 64-char hex string (32 bytes)
///
/// # Returns
/// Hex-encoded metadata bytes (0x-prefixed).
#[wasm_bindgen]
pub fn encode_v2_attestation_metadata_wasm(
    view_tag: u8,
    schema_id_hex: &str,
    issuer_hex: &str,
    attestation_uid_hex: &str,
    nonce_hex: &str,
) -> Result<String, JsValue> {
    let schema_id = parse_hex32(schema_id_hex)?;
    let issuer = parse_hex32(issuer_hex)?;
    let attestation_uid = parse_hex32(attestation_uid_hex)?;
    let nonce = parse_hex32(nonce_hex)?;

    let metadata = attestation::encode_v2_attestation_metadata(
        view_tag,
        &schema_id,
        &issuer,
        &attestation_uid,
        &nonce,
    );
    Ok(format!("0x{}", metadata.iter().map(|b| format!("{:02x}", b)).collect::<String>()))
}

/// Scans V2 announcements for schema-bound attestations belonging to this recipient.
///
/// Unlike V1, V2 requires a schema registry snapshot to validate issuer authorization.
/// Rogue traits (issued by non-delegates) are filtered out before results are returned.
///
/// # Arguments
/// * `announcements_json` - JSON array of announcement objects (same format as V1)
/// * `schemas_json` - JSON array of SchemaInfo objects fetched from schema_registry program
/// * `view_privkey_bytes` - 32-byte viewing private key (Uint8Array)
/// * `spend_pubkey_bytes` - 33-byte spending public key (compressed, Uint8Array)
/// * `current_slot` - Current Solana slot for expiry checks
/// * `trusted_issuers_json` - Optional JSON array of trusted issuer hex strings; pass "" to skip
///
/// # Returns
/// JSON array of V2StealthAttestation objects.
#[wasm_bindgen]
pub fn scan_attestations_v2_wasm(
    announcements_json: &str,
    schemas_json: &str,
    view_privkey_bytes: &[u8],
    spend_pubkey_bytes: &[u8],
    current_slot: u64,
    trusted_issuers_json: &str,
) -> Result<String, JsValue> {
    let view_privkey = bytes_to_signing_key(view_privkey_bytes)?;
    let spend_pubkey = bytes_to_public_key(spend_pubkey_bytes)?;

    // Parse announcements (reuse V1 parser)
    let raw_anns: Vec<serde_json::Value> = serde_json::from_str(announcements_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid announcements JSON: {}", e)))?;

    let mut announcements = Vec::with_capacity(raw_anns.len());
    for ann in &raw_anns {
        let stealth_addr_str = ann["stealthAddress"].as_str().unwrap_or_default();
        let stealth_address = hex_to_address(stealth_addr_str)?;
        let view_tag = ann["viewTag"].as_u64().unwrap_or(0) as u8;
        let eph_hex = ann["ephemeralPubKey"].as_str().unwrap_or_default();
        let eph_clean = eph_hex.strip_prefix("0x").unwrap_or(eph_hex);
        let eph_bytes = hex::decode(eph_clean)
            .map_err(|e| JsValue::from_str(&format!("Invalid ephemeral pubkey: {}", e)))?;
        let ephemeral_pubkey = bytes_to_public_key(&eph_bytes)?;
        let meta_hex = ann["metadata"].as_str().unwrap_or_default();
        let meta_clean = meta_hex.strip_prefix("0x").unwrap_or(meta_hex);
        let metadata = hex::decode(meta_clean).unwrap_or_default();
        let tx_hash = ann["txHash"].as_str().unwrap_or_default().to_string();
        let block_number = ann["blockNumber"].as_u64().unwrap_or(0);
        announcements.push(RawAnnouncement {
            stealth_address,
            view_tag,
            ephemeral_pubkey,
            metadata,
            tx_hash,
            block_number,
        });
    }

    // Parse schema registry snapshot
    let schemas: Vec<SchemaInfo> = serde_json::from_str(schemas_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid schemas JSON: {}", e)))?;

    // Parse optional trusted issuer allowlist
    let trusted_set: Option<std::collections::HashSet<String>> =
        if trusted_issuers_json.is_empty() || trusted_issuers_json == "[]" {
            None
        } else {
            let list: Vec<String> = serde_json::from_str(trusted_issuers_json)
                .map_err(|e| JsValue::from_str(&format!("Invalid trusted_issuers JSON: {}", e)))?;
            Some(list.into_iter().collect())
        };

    // Browser scans always drop unauthorized-issuer traits (include_unauthorized = false):
    // the announcement layer is permissionless, so surfacing them would let forged reputation
    // reach any consumer that trusts the documented "filtered" behaviour (OPQ-011).
    let results = scan_for_attestations_v2(
        &announcements,
        &view_privkey,
        &spend_pubkey,
        &schemas,
        current_slot,
        trusted_set.as_ref(),
        false,
    )
    .map_err(|e| JsValue::from_str(&format!("V2 scan error: {}", e)))?;

    serde_json::to_string(&results)
        .map_err(|e| JsValue::from_str(&format!("Serialize error: {}", e)))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_hex32(hex: &str) -> Result<[u8; 32], JsValue> {
    let clean = hex.trim_start_matches("0x");
    let bytes = hex::decode(clean)
        .map_err(|e| JsValue::from_str(&format!("Invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("Expected exactly 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

