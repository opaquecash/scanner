# opaque-scanner

Stealth-address (DKSAP) scanner for [Opaque Cash](https://opaque.cash) — the shared,
chain-neutral cryptography core used by the Ethereum and Solana clients. Compiles to
native Rust **and** WebAssembly, so the same code scans in a browser with no server.

It implements the [EIP-5564](https://eips.ethereum.org/EIPS/eip-5564) Dual-Key Stealth
Address Protocol over secp256k1, plus the Opaque Programmable Stealth Reputation (PSR)
attestation layer (V1 and V2). See the protocol spec
[CSAP.md](https://github.com/opaquecash/spec/blob/main/CSAP.md).

## What it does

- **Stealth address derivation** — `P_stealth = P_spend + keccak256(ECDH(p_view, R))·G`.
- **View-tag pre-filter** — one byte lets a scanner skip ~99.6% of announcements
  before any elliptic-curve work.
- **One-time key recovery** — reconstructs the spendable private key for a matched
  stealth address.
- **PSR attestations** — V1 attestation-id metadata and V2 schema-bound, issuer-verified
  traits (`scan_for_attestations`, `scan_for_attestations_v2`).
- **Merkle witnesses** — builds inclusion proofs for the Circom reputation circuits.
- **`ChainAdapter` trait** (`dksap` module) — the chain-neutral seam the universal
  cross-chain scanner is built on; concrete Ethereum/Solana adapters live in the SDK.

## Install

```sh
cargo add opaque-scanner
```

## Rust usage

```rust
use opaque_scanner::scanner::{derive_stealth_address, check_announcement};
// derive_stealth_address(&view_privkey, &spend_pubkey, &ephemeral_pubkey)
//   -> (stealth_address, view_tag)
```

The crate also re-exports the shared core under `opaque_scanner::dksap` and defines
`dksap::ChainAdapter` / `dksap::Announcement` for multi-chain scan loops.

## WebAssembly

```sh
wasm-pack build --target web --release   # emits cryptography_bg.wasm + cryptography.js
```

The `#[wasm_bindgen]` exports (`derive_stealth_address_wasm`, `check_announcement_wasm`,
`scan_for_attestations`, `scan_for_attestations_v2`, …) are what the Opaque web clients
load directly in the browser.

## Test vectors

DKSAP outputs are cross-validated byte-for-byte against an independent Python reference
and the `@noble` TypeScript path; the pinned vectors live in
[`opaquecash/circuits`](https://github.com/opaquecash/circuits) (`test/test_vectors.json`)
and are asserted by `scanner::tests::matches_csap_test_vectors`.

## Links

- Spec: <https://github.com/opaquecash/spec>
- Source: <https://github.com/opaquecash/scanner>
- App: <https://opaque.cash>

## License

MIT
