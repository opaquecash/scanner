//! The universal scanner (guide Task 0.4): one dedup + view-tag + DKSAP loop over any
//! set of [`ChainAdapter`]s. Adapters fetch chain-native announcements into the
//! chain-neutral [`Announcement`] shape; this module decides ownership once,
//! identically for every chain.

use std::collections::HashSet;
use std::str::FromStr;

use alloy_primitives::Address;
use k256::{ecdsa::SigningKey, PublicKey};

use crate::dksap::{Announcement, ChainAdapter};
use crate::scanner::{check_announcement, check_announcement_view_tag, ViewTagCheck};

/// Error from one adapter during a multi-chain scan, with the adapter's name attached.
#[derive(Debug)]
pub struct AdapterError {
    /// `ChainAdapter::name()` of the failing adapter.
    pub adapter: String,
    /// Debug-formatted adapter error.
    pub message: String,
}

impl core::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} adapter: {}", self.adapter, self.message)
    }
}

/// Object-safe view of [`ChainAdapter`] (errors stringified) so heterogeneous
/// adapters — different `Error` types — can be scanned in one loop. Implemented
/// automatically for every `ChainAdapter`.
pub trait DynChainAdapter {
    /// Wormhole chain id this adapter serves.
    fn chain_id(&self) -> u16;
    /// Human-readable adapter name.
    fn name(&self) -> &str;
    /// Type-erased [`ChainAdapter::fetch_announcements`].
    fn fetch_announcements_dyn(&self, cursor: u64) -> Result<Vec<Announcement>, AdapterError>;
}

impl<A: ChainAdapter> DynChainAdapter for A {
    fn chain_id(&self) -> u16 {
        ChainAdapter::chain_id(self)
    }

    fn name(&self) -> &str {
        ChainAdapter::name(self)
    }

    fn fetch_announcements_dyn(&self, cursor: u64) -> Result<Vec<Announcement>, AdapterError> {
        self.fetch_announcements(cursor).map_err(|e| AdapterError {
            adapter: ChainAdapter::name(self).to_owned(),
            message: format!("{e:?}"),
        })
    }
}

/// Errors constructing a [`UniversalScanner`].
#[derive(Debug, PartialEq, Eq)]
pub enum UniversalScannerError {
    /// Viewing key was not 32 bytes or not a valid scalar.
    InvalidViewingKey,
    /// Spending public key was not a valid SEC1 point.
    InvalidSpendingPublicKey,
}

/// One recipient's cross-chain scanner: holds the viewing private key and spending
/// public key, fetches via any adapters, and returns only owned announcements.
///
/// Per CSAP, the 20-byte EVM-style stealth address is the matching identifier on
/// every chain, so a single scan loop covers Ethereum, Solana, and relayed (UAB)
/// announcements alike.
#[derive(Debug)]
pub struct UniversalScanner {
    view_privkey: SigningKey,
    spend_pubkey: PublicKey,
}

impl UniversalScanner {
    /// Build from a 32-byte viewing private key and a SEC1 (33- or 65-byte)
    /// spending public key.
    pub fn new(
        viewing_key: &[u8],
        spend_pubkey_sec1: &[u8],
    ) -> Result<Self, UniversalScannerError> {
        let view_privkey = SigningKey::from_slice(viewing_key)
            .map_err(|_| UniversalScannerError::InvalidViewingKey)?;
        let spend_pubkey = PublicKey::from_sec1_bytes(spend_pubkey_sec1)
            .map_err(|_| UniversalScannerError::InvalidSpendingPublicKey)?;
        Ok(Self {
            view_privkey,
            spend_pubkey,
        })
    }

    /// Fetch from every adapter (cursor is adapter-interpreted: EVM block or Solana
    /// slot) and return the deduplicated announcements owned by this recipient.
    pub fn scan(
        &self,
        adapters: &[&dyn DynChainAdapter],
        cursor: u64,
    ) -> Result<Vec<Announcement>, AdapterError> {
        let mut all = Vec::new();
        for adapter in adapters {
            all.extend(adapter.fetch_announcements_dyn(cursor)?);
        }
        Ok(self.filter_owned(&all))
    }

    /// The shared ownership loop: dedup (a UAB-relayed copy keeps its origin
    /// `chain_id`, so it collapses onto the native original), cheap view-tag
    /// pre-filter, then full DKSAP recovery. Malformed announcements (bad hex,
    /// non-point ephemeral keys) are skipped, never fatal — anyone can announce.
    pub fn filter_owned(&self, announcements: &[Announcement]) -> Vec<Announcement> {
        let mut seen = HashSet::new();
        let mut owned = Vec::new();
        for ann in announcements {
            let key = (
                ann.chain_id,
                ann.stealth_address.to_ascii_lowercase(),
                ann.ephemeral_pubkey.clone(),
                ann.view_tag,
            );
            if !seen.insert(key) {
                continue;
            }
            let Ok(address) = Address::from_str(&ann.stealth_address) else {
                continue;
            };
            let Ok(ephemeral) = PublicKey::from_sec1_bytes(&ann.ephemeral_pubkey) else {
                continue;
            };
            if matches!(
                check_announcement_view_tag(ann.view_tag, &self.view_privkey, &ephemeral),
                ViewTagCheck::NoMatch
            ) {
                continue;
            }
            if check_announcement(
                address,
                ann.view_tag,
                &self.view_privkey,
                &self.spend_pubkey,
                &ephemeral,
            )
            .unwrap_or(false)
            {
                owned.push(ann.clone());
            }
        }
        owned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::derive_stealth_address;

    /// Deterministic recipient + sender material (same convention as scanner tests).
    fn test_setup() -> (SigningKey, PublicKey, Announcement) {
        let view_privkey = SigningKey::from_slice(&[0xAA; 32]).unwrap();
        let spend_privkey = SigningKey::from_slice(&[0xBB; 32]).unwrap();
        let spend_pubkey = PublicKey::from(spend_privkey.verifying_key());
        let ephemeral_privkey = SigningKey::from_slice(&[0xCC; 32]).unwrap();
        let ephemeral_pubkey = PublicKey::from(ephemeral_privkey.verifying_key());
        let (address, view_tag) =
            derive_stealth_address(&view_privkey, &spend_pubkey, &ephemeral_pubkey).unwrap();
        let ann = Announcement {
            stealth_address: format!("{address:#x}"),
            ephemeral_pubkey: ephemeral_pubkey.to_sec1_bytes().to_vec(),
            view_tag,
            metadata: vec![view_tag],
            chain_id: 2,
        };
        (view_privkey, spend_pubkey, ann)
    }

    struct MockAdapter {
        chain_id: u16,
        name: &'static str,
        announcements: Vec<Announcement>,
    }

    impl ChainAdapter for MockAdapter {
        type Error = String;

        fn chain_id(&self) -> u16 {
            self.chain_id
        }

        fn name(&self) -> &str {
            self.name
        }

        fn fetch_announcements(&self, _cursor: u64) -> Result<Vec<Announcement>, String> {
            Ok(self.announcements.clone())
        }
    }

    fn scanner_for(view: &SigningKey, spend: &PublicKey) -> UniversalScanner {
        UniversalScanner::new(&view.to_bytes(), &spend.to_sec1_bytes()).unwrap()
    }

    #[test]
    fn rejects_invalid_keys() {
        assert_eq!(
            UniversalScanner::new(&[0u8; 31], &[2u8; 33]).unwrap_err(),
            UniversalScannerError::InvalidViewingKey
        );
        assert_eq!(
            UniversalScanner::new(&[0xAA; 32], &[0u8; 33]).unwrap_err(),
            UniversalScannerError::InvalidSpendingPublicKey
        );
    }

    #[test]
    fn finds_owned_announcement_and_skips_noise() {
        let (view, spend, owned_ann) = test_setup();
        let scanner = scanner_for(&view, &spend);

        // Decoy with a flipped view tag (cheap filter), one with a wrong address
        // (full check), and one malformed (non-point ephemeral key).
        let mut wrong_tag = owned_ann.clone();
        wrong_tag.view_tag = owned_ann.view_tag.wrapping_add(1);
        let mut wrong_address = owned_ann.clone();
        wrong_address.stealth_address = format!("0x{}", "11".repeat(20));
        let mut malformed = owned_ann.clone();
        malformed.ephemeral_pubkey = vec![0x02; 33];

        let result =
            scanner.filter_owned(&[wrong_tag, wrong_address, malformed, owned_ann.clone()]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].stealth_address, owned_ann.stealth_address);
    }

    #[test]
    fn dedups_relayed_copies_by_origin_chain_id() {
        let (view, spend, owned_ann) = test_setup();
        let scanner = scanner_for(&view, &spend);

        // A UAB-relayed copy keeps the origin chain_id (2), so it dedups against the
        // native original; the same payment announced natively on the OTHER chain
        // (different chain_id) is a distinct announcement.
        let relayed_copy = owned_ann.clone();
        let mut other_chain = owned_ann.clone();
        other_chain.chain_id = 1;

        let result = scanner.filter_owned(&[owned_ann, relayed_copy, other_chain]);
        assert_eq!(result.len(), 2);
        let chains: Vec<u16> = result.iter().map(|a| a.chain_id).collect();
        assert!(chains.contains(&1) && chains.contains(&2));
    }

    #[test]
    fn scans_heterogeneous_adapters_in_one_loop() {
        let (view, spend, owned_ann) = test_setup();
        let scanner = scanner_for(&view, &spend);

        let mut decoy = owned_ann.clone();
        decoy.view_tag = owned_ann.view_tag.wrapping_add(1);
        let eth = MockAdapter {
            chain_id: 2,
            name: "ethereum",
            announcements: vec![owned_ann.clone(), decoy],
        };
        let mut solana_native = owned_ann.clone();
        solana_native.chain_id = 1;
        let sol = MockAdapter {
            chain_id: 1,
            name: "solana",
            announcements: vec![solana_native, owned_ann.clone()], // second = relayed dup
        };

        let result = scanner.scan(&[&eth, &sol], 0).unwrap();
        assert_eq!(result.len(), 2, "one per origin chain after dedup");
    }

    #[test]
    fn surfaces_adapter_errors_with_the_adapter_name() {
        struct Failing;
        impl ChainAdapter for Failing {
            type Error = &'static str;
            fn chain_id(&self) -> u16 {
                2
            }
            fn name(&self) -> &str {
                "failing"
            }
            fn fetch_announcements(&self, _: u64) -> Result<Vec<Announcement>, Self::Error> {
                Err("rpc down")
            }
        }
        let (view, spend, _) = test_setup();
        let scanner = scanner_for(&view, &spend);
        let err = scanner.scan(&[&Failing], 0).unwrap_err();
        assert_eq!(err.adapter, "failing");
        assert!(err.to_string().contains("rpc down"));
    }
}
