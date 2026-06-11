//! Chain-agnostic DKSAP core and the [`ChainAdapter`] abstraction.
//!
//! The DKSAP *payment* layer — key derivation, view-tag matching, stealth-address
//! recovery, Merkle witnesses, and the V1/V2 attestation logic — is identical across
//! chains. Only *how announcements are fetched and submitted* differs. This module is
//! the shared, chain-neutral surface; [`ChainAdapter`] captures the per-chain part so
//! the scan loop can be written once.
//!
//! This module re-exports the shared core and defines [`ChainAdapter`]. Concrete
//! adapters live in [`crate::adapters`] (`ethereum`, `solana`; JSON-RPC transports
//! behind the `native` feature), and [`crate::universal::UniversalScanner`] runs the
//! shared dedup + view-tag + DKSAP loop over any set of them.

// Shared, chain-neutral core. Re-exported here so consumers depend on a single
// `dksap` surface rather than reaching into individual modules.
pub use crate::attestation;
pub use crate::merkle;
pub use crate::scanner;

/// A chain-agnostic stealth announcement as surfaced by a [`ChainAdapter`].
///
/// This is the common shape the universal scanner consumes; each adapter decodes its
/// chain's native event/log into this struct.
#[derive(Clone, Debug)]
pub struct Announcement {
    /// Scanner-matching identifier: 20-byte EVM-style stealth address, `0x`-prefixed.
    pub stealth_address: String,
    /// Sender ephemeral public key, 33-byte compressed secp256k1.
    pub ephemeral_pubkey: Vec<u8>,
    /// View tag (`metadata[0]`) for the cheap pre-filter.
    pub view_tag: u8,
    /// Raw announcement metadata (scheme-specific payload).
    pub metadata: Vec<u8>,
    /// Wormhole chain id of the source chain (Ethereum = 2, Solana = 1).
    pub chain_id: u16,
}

/// Abstracts chain-specific announcement retrieval so the scan loop is shared.
///
/// The universal scanner iterates over a set of adapters, calls
/// [`ChainAdapter::fetch_announcements`], then runs the shared view-tag filter and
/// DKSAP recovery on the returned [`Announcement`]s.
pub trait ChainAdapter {
    /// Adapter-specific error type.
    type Error: core::fmt::Debug;

    /// Wormhole chain id this adapter serves.
    fn chain_id(&self) -> u16;

    /// Human-readable adapter name, e.g. `"ethereum"` or `"solana"`.
    fn name(&self) -> &str;

    /// Fetch announcements at or after `cursor` (an EVM block number or a Solana
    /// slot, interpreted by the adapter), in the chain-neutral [`Announcement`] form.
    fn fetch_announcements(&self, cursor: u64) -> Result<Vec<Announcement>, Self::Error>;
}
