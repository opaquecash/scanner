//! # Opaque Cash — Scanner Engine (EIP-5564 / DKSAP)
//!
//! Dual-Key Stealth Address Protocol: derives stealth addresses from announcements
//! and filters them efficiently using view tags before expensive EC operations.

use alloy_primitives::Address;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{ecdsa::SigningKey, PublicKey, ProjectivePoint, Scalar, U256};
use sha3::{Digest, Keccak256};

// =============================================================================
// Data structures (EIP-5564 stealth meta-address)
// =============================================================================

/// Stealth meta-address: the two public keys a recipient publishes for DKSAP.
/// Senders use this to derive a one-time stealth address; scanners use it with
/// the viewing key to detect incoming transfers.
#[derive(Clone, Debug)]
pub struct StealthMetaAddress {
    /// Viewing public key (used by sender to compute shared secret with ephemeral key).
    pub view_pubkey: PublicKey,
    /// Spending public key (base for stealth address: P_stealth = P_spend + s_h*G).
    pub spend_pubkey: PublicKey,
}

impl StealthMetaAddress {
    pub fn new(view_pubkey: PublicKey, spend_pubkey: PublicKey) -> Self {
        Self {
            view_pubkey,
            spend_pubkey,
        }
    }
}

// =============================================================================
// DKSAP: shared secret and hashed secret (EIP-5564 math)
// =============================================================================

/// Computes the raw ECDH shared secret: `s = p_view * P_ephemeral`.
///
/// We do raw scalar-point multiplication (not the standard ECDH, which applies
/// an extra hash). EIP-5564 hashes `s` separately with Keccak-256.
/// The shared secret is the compressed encoding of the resulting curve point.
fn shared_secret_bytes(view_privkey: &SigningKey, ephemeral_pubkey: &PublicKey) -> [u8; 33] {
    let view_scalar: &Scalar = view_privkey.as_nonzero_scalar().as_ref();
    let ephemeral_point = ephemeral_pubkey.to_projective();
    let shared_point = (ephemeral_point * view_scalar).to_affine();
    let encoded = shared_point.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

/// Hashes the shared secret with Keccak-256 per EIP-5564: `s_h = h(s)`.
/// Returns the 32-byte hash; the first byte is the view tag.
fn hash_shared_secret(shared_secret: &[u8; 33]) -> [u8; 32] {
    Keccak256::digest(shared_secret).into()
}

/// View tag: most significant byte of `s_h`. Used to skip full derivation for
/// non-matching announcements (~255/256 of them).
#[inline]
pub fn view_tag_from_hashed_secret(secret_hash: &[u8; 32]) -> u8 {
    secret_hash[0]
}

// =============================================================================
// Stealth address derivation (DKSAP)
// =============================================================================

/// Derives the stealth address and view tag for a single announcement.
///
/// **DKSAP steps (EIP-5564):**
/// 1. Shared secret: `s = p_view * P_ephemeral` (ECDH).
/// 2. Hash: `s_h = Keccak256(s)`.
/// 3. View tag: `v = s_h[0]` (for scanner filter).
/// 4. Point: `S_h = s_h * G` (scalar mult on generator).
/// 5. Stealth public key: `P_stealth = P_spend + S_h` (point addition).
/// 6. Address: `address = keccak256(uncompressed(P_stealth))[12..32]`.
pub fn derive_stealth_address(
    view_privkey: &SigningKey,
    spend_pubkey: &PublicKey,
    ephemeral_pubkey: &PublicKey,
) -> Result<(Address, u8), StealthAddressError> {
    // Step 1: Shared secret s = p_view * P_ephemeral
    let s = shared_secret_bytes(view_privkey, ephemeral_pubkey);
    // Step 2: s_h = h(s)
    let s_h = hash_shared_secret(&s);
    // Step 3: view tag (most significant byte)
    let view_tag = view_tag_from_hashed_secret(&s_h);
    // Step 4: S_h = s_h * G. Reduce s_h modulo the curve order n (rather than
    // rejecting s_h >= n) so a valid payment is never orphaned — this matches the
    // CSAP spec and the TS SDK, which both reduce mod n. A zero scalar (s_h ≡ 0)
    // is still rejected: it would collapse S_h to the point at infinity.
    let repr = k256::FieldBytes::from(s_h);
    let s_h_scalar = <Scalar as Reduce<U256>>::reduce_bytes(&repr);
    if bool::from(s_h_scalar.is_zero()) {
        return Err(StealthAddressError::InvalidScalar);
    }
    let s_h_point = ProjectivePoint::GENERATOR * s_h_scalar;
    // Step 5: P_stealth = P_spend + S_h
    let spend_affine = spend_pubkey.to_projective();
    let p_stealth_proj = spend_affine + s_h_point;
    let p_stealth_affine = p_stealth_proj.to_affine();
    let p_stealth = PublicKey::from_affine(p_stealth_affine)
        .map_err(|_| StealthAddressError::InvalidPoint)?;
    // Step 6: Ethereum address from uncompressed pubkey (Keccak256, then last 20 bytes)
    let address = pubkey_to_address(&p_stealth);
    Ok((address, view_tag))
}

/// Converts a secp256k1 public key to an Ethereum address per EIP-55 / standard.
fn pubkey_to_address(pubkey: &PublicKey) -> Address {
    let uncompressed = pubkey.to_encoded_point(false);
    // Skip the leading 0x04 tag byte; hash the raw 64-byte (x ‖ y)
    let hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
    Address::from_slice(&hash[12..32])
}

/// Derives the one-time stealth signing key (private key) for spending from a stealth address.
///
/// **DKSAP:** `p_stealth = p_spend + s_h` (scalar addition mod n), where
/// `s_h = Keccak256(shared_secret)` and shared secret is from view key and ephemeral pubkey.
/// Caller must use this key only with the matching stealth address.
pub fn derive_stealth_signing_key(
    view_privkey: &SigningKey,
    spend_privkey: &SigningKey,
    ephemeral_pubkey: &PublicKey,
) -> Result<[u8; 32], StealthAddressError> {
    let s = shared_secret_bytes(view_privkey, ephemeral_pubkey);
    let s_h = hash_shared_secret(&s);
    // Reduce mod n (not reject) so this agrees with derive_stealth_address and the
    // TS SDK; reject a zero hashed secret and a zero resulting one-time key.
    let repr = k256::FieldBytes::from(s_h);
    let s_h_scalar = <Scalar as Reduce<U256>>::reduce_bytes(&repr);
    if bool::from(s_h_scalar.is_zero()) {
        return Err(StealthAddressError::InvalidScalar);
    }
    let spend_scalar: &Scalar = spend_privkey.as_nonzero_scalar().as_ref();
    let p_stealth_scalar = spend_scalar + s_h_scalar;
    if bool::from(p_stealth_scalar.is_zero()) {
        return Err(StealthAddressError::InvalidScalar);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(p_stealth_scalar.to_repr().as_ref());
    Ok(out)
}

// =============================================================================
// Scanner filter: view-tag check before expensive EC (EIP-5564 parsing)
// =============================================================================

/// Result of a quick view-tag check: either a definite "no" or "maybe, need full check".
#[derive(Debug)]
pub enum ViewTagCheck {
    /// View tag did not match; skip EC addition for this announcement.
    NoMatch,
    /// View tag matched; caller should run full derivation to confirm.
    PossibleMatch,
}

/// Checks the announcement's view tag against the local secret hash **before**
/// doing the expensive elliptic curve addition. If the view tag does not match,
/// the announcement is not for this recipient (~255/256 of announcements).
///
/// Returns:
/// - `ViewTagCheck::NoMatch` — safe to skip; no need to call `derive_stealth_address`.
/// - `ViewTagCheck::PossibleMatch` — view tag matches; call `derive_stealth_address`
///   and compare the resulting address with the announcement's stealth address.
pub fn check_announcement_view_tag(
    view_tag: u8,
    view_privkey: &SigningKey,
    ephemeral_pubkey: &PublicKey,
) -> ViewTagCheck {
    let s = shared_secret_bytes(view_privkey, ephemeral_pubkey);
    let s_h = hash_shared_secret(&s);
    let local_view_tag = view_tag_from_hashed_secret(&s_h);
    if view_tag != local_view_tag {
        ViewTagCheck::NoMatch
    } else {
        ViewTagCheck::PossibleMatch
    }
}

/// Full check: view-tag filter first, then full derivation and address comparison.
/// Returns `true` iff the announcement's stealth address belongs to this recipient.
pub fn check_announcement(
    announcement_stealth_address: Address,
    view_tag: u8,
    view_privkey: &SigningKey,
    spend_pubkey: &PublicKey,
    ephemeral_pubkey: &PublicKey,
) -> Result<bool, StealthAddressError> {
    // Fast path: avoid EC addition when view tag does not match
    match check_announcement_view_tag(view_tag, view_privkey, ephemeral_pubkey) {
        ViewTagCheck::NoMatch => return Ok(false),
        ViewTagCheck::PossibleMatch => {}
    }
    let (derived_address, _) = derive_stealth_address(view_privkey, spend_pubkey, ephemeral_pubkey)?;
    Ok(derived_address == announcement_stealth_address)
}

// =============================================================================
// Errors
// =============================================================================

#[derive(Debug)]
pub enum StealthAddressError {
    InvalidScalar,
    InvalidPoint,
}

impl std::fmt::Display for StealthAddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StealthAddressError::InvalidScalar => write!(f, "hashed shared secret out of curve order"),
            StealthAddressError::InvalidPoint => write!(f, "invalid stealth public key point"),
        }
    }
}

impl std::error::Error for StealthAddressError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use k256::PublicKey;

    /// Simulates the full EIP-5564 flow:
    ///   Sender generates ephemeral key → derives stealth address
    ///   Scanner checks the announcement → must match
    #[test]
    fn round_trip_derive_and_check() {
        // Recipient key pairs
        let view_privkey = SigningKey::from_bytes(&[0xaa; 32].into()).unwrap();
        let spend_privkey = SigningKey::from_bytes(&[0xbb; 32].into()).unwrap();
        let spend_pubkey = PublicKey::from(spend_privkey.verifying_key());

        // Sender generates an ephemeral key pair
        let ephemeral_privkey = SigningKey::from_bytes(&[0xcc; 32].into()).unwrap();
        let ephemeral_pubkey = PublicKey::from(ephemeral_privkey.verifying_key());

        // --- Sender side: derive stealth address ---
        // Sender knows (P_view, P_spend) from stealth meta-address and has p_ephemeral.
        // Shared secret from sender perspective: s = p_ephemeral * P_view
        let view_pubkey = PublicKey::from(view_privkey.verifying_key());
        let sender_shared = {
            let eph_scalar: &Scalar = ephemeral_privkey.as_nonzero_scalar().as_ref();
            let view_point = view_pubkey.to_projective();
            let pt = (view_point * eph_scalar).to_affine();
            let enc = pt.to_encoded_point(true);
            let mut buf = [0u8; 33];
            buf.copy_from_slice(enc.as_bytes());
            buf
        };
        let sender_s_h = hash_shared_secret(&sender_shared);
        let sender_view_tag = view_tag_from_hashed_secret(&sender_s_h);
        let sender_s_h_scalar = Scalar::from_repr(k256::FieldBytes::from(sender_s_h)).into_option().unwrap();
        let sender_s_h_point = ProjectivePoint::GENERATOR * sender_s_h_scalar;
        let stealth_point = spend_pubkey.to_projective() + sender_s_h_point;
        let stealth_pk = PublicKey::from_affine(stealth_point.to_affine()).unwrap();
        let stealth_address = {
            let uncompressed = stealth_pk.to_encoded_point(false);
            let hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
            Address::from_slice(&hash[12..32])
        };

        // --- Scanner side: verify using check_announcement ---
        let result = check_announcement(
            stealth_address,
            sender_view_tag,
            &view_privkey,
            &spend_pubkey,
            &ephemeral_pubkey,
        )
        .expect("check_announcement should not fail");

        assert!(result, "scanner must recognise its own stealth address");
    }

    /// Ensures a wrong view tag causes an early reject (no EC addition).
    #[test]
    fn wrong_view_tag_rejects() {
        let view_privkey = SigningKey::from_bytes(&[0xaa; 32].into()).unwrap();
        let spend_privkey = SigningKey::from_bytes(&[0xbb; 32].into()).unwrap();
        let spend_pubkey = PublicKey::from(spend_privkey.verifying_key());

        let ephemeral_privkey = SigningKey::from_bytes(&[0xcc; 32].into()).unwrap();
        let ephemeral_pubkey = PublicKey::from(ephemeral_privkey.verifying_key());

        let (stealth_address, correct_tag) =
            derive_stealth_address(&view_privkey, &spend_pubkey, &ephemeral_pubkey).unwrap();

        let wrong_tag = correct_tag.wrapping_add(1);
        let result = check_announcement(
            stealth_address,
            wrong_tag,
            &view_privkey,
            &spend_pubkey,
            &ephemeral_pubkey,
        )
        .unwrap();

        assert!(!result, "wrong view tag must reject");
    }

    /// Verifies that derive_stealth_address called from the scanner side
    /// produces the same address as the sender-side derivation.
    #[test]
    fn scanner_derive_matches_sender() {
        let view_privkey = SigningKey::from_bytes(&[0x11; 32].into()).unwrap();
        let spend_privkey = SigningKey::from_bytes(&[0x22; 32].into()).unwrap();
        let spend_pubkey = PublicKey::from(spend_privkey.verifying_key());

        let ephemeral_privkey = SigningKey::from_bytes(&[0x33; 32].into()).unwrap();
        let ephemeral_pubkey = PublicKey::from(ephemeral_privkey.verifying_key());

        let (addr, tag) =
            derive_stealth_address(&view_privkey, &spend_pubkey, &ephemeral_pubkey).unwrap();

        // Derive again — must be deterministic
        let (addr2, tag2) =
            derive_stealth_address(&view_privkey, &spend_pubkey, &ephemeral_pubkey).unwrap();

        assert_eq!(addr, addr2);
        assert_eq!(tag, tag2);
    }

    /// OPQ-025: a hashed secret `s_h >= n` must be *reduced* mod n, not rejected.
    /// The old `Scalar::from_repr` path returned `None` for any value in `[n, 2^256)`,
    /// which silently orphaned payments whose ECDH hash exceeded the curve order,
    /// diverging from the reduce-mod-n senders (CSAP spec + TS SDK). `reduce_bytes`
    /// accepts those values; this pins the well-defined boundary cases n and n+1.
    #[test]
    fn hashed_secret_reduces_mod_n_instead_of_rejecting() {
        // secp256k1 group order n, big-endian (FieldBytes are big-endian scalars).
        let n_bytes: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];

        // The rejected-before path: from_repr yields None for n (out of [0, n)).
        assert!(
            bool::from(Scalar::from_repr(k256::FieldBytes::from(n_bytes)).is_none()),
            "from_repr must reject n (the old orphaning behavior)"
        );

        // The fixed path: reduce_bytes(n) == 0 mod n.
        let reduced_n = <Scalar as Reduce<U256>>::reduce_bytes(&k256::FieldBytes::from(n_bytes));
        assert!(bool::from(reduced_n.is_zero()), "n must reduce to 0 mod n");

        // reduce_bytes(n + 1) == 1 mod n.
        let mut np1 = n_bytes;
        np1[31] = np1[31].wrapping_add(1); // 0x41 -> 0x42, i.e. n + 1
        let reduced_np1 = <Scalar as Reduce<U256>>::reduce_bytes(&k256::FieldBytes::from(np1));
        assert_eq!(reduced_np1, Scalar::from(1u64), "n + 1 must reduce to 1 mod n");
    }

    /// Cross-validation against the canonical CSAP test vectors
    /// (`opaquecash/circuits/test/test_vectors.json`), which are generated by an
    /// independent pure-Python secp256k1/Keccak implementation. Pinning the expected
    /// outputs here proves the scanner agrees with the spec vectors byte-for-byte.
    /// Keep in sync with `circuits/test/test_vectors.json`.
    #[test]
    #[allow(clippy::type_complexity)] // compact test-fixture tuple; a struct adds noise here
    fn matches_csap_test_vectors() {
        let to_hex = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
        // (view, spend, ephemeral, expected view_tag, stealth address, one-time signing key)
        let cases: [([u8; 32], [u8; 32], [u8; 32], u8, &str, &str); 3] = [
            (
                [0xaa; 32], [0xbb; 32], [0xcc; 32], 225,
                "a5847a467208cbcd5d238369865a90716310183a",
                "9d1fcbe17267729a88091556cadd19b3c11e33029883163d1d7118bc21a61e2e",
            ),
            (
                [0xaa; 32], [0xbb; 32], [0xdd; 32], 250,
                "0fb5e1f647f42a038cc3c69cce930807e1b3708b",
                "b654efde2aa534416cebe837d9419ce90679e81104f5f26fa3bf473ee99119c0",
            ),
            (
                [0x11; 32], [0x22; 32], [0x33; 32], 89,
                "6ba3fd25ea94e91b2fa18b8b00d52b415cfc8bcf",
                "7b316cd7601c63dc2da9ee93ef11f815e6006ffe3787cc3d4e9493c606ff4203",
            ),
        ];
        for (v, s, e, expected_tag, expected_addr, expected_otk) in cases {
            let view_privkey = SigningKey::from_bytes(&v.into()).unwrap();
            let spend_privkey = SigningKey::from_bytes(&s.into()).unwrap();
            let spend_pubkey = PublicKey::from(spend_privkey.verifying_key());
            let ephemeral_pubkey =
                PublicKey::from(SigningKey::from_bytes(&e.into()).unwrap().verifying_key());

            let (addr, view_tag) =
                derive_stealth_address(&view_privkey, &spend_pubkey, &ephemeral_pubkey).unwrap();
            assert_eq!(view_tag, expected_tag, "view tag mismatch");
            assert_eq!(to_hex(addr.as_slice()), expected_addr, "stealth address mismatch");

            let otk =
                derive_stealth_signing_key(&view_privkey, &spend_privkey, &ephemeral_pubkey).unwrap();
            assert_eq!(to_hex(&otk), expected_otk, "one-time signing key mismatch");
        }
    }
}
