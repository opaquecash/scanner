//! Universal cross-chain scan over the live deployments (Sepolia + Solana devnet):
//!
//! ```sh
//! cargo run --example universal_scan --features native
//! ```
//!
//! Env overrides: `SEPOLIA_RPC_URL`, `SOLANA_RPC_URL`, `VIEWING_KEY` /
//! `SPENDING_PUBKEY` (hex; defaults are the CSAP test-vector keys, which own
//! nothing on-chain — the run demonstrates fetch + decode + filter).

use cryptography::adapters::ethereum::EthereumAdapter;
use cryptography::adapters::solana::SolanaAdapter;
use cryptography::universal::{DynChainAdapter, UniversalScanner};
use k256::ecdsa::SigningKey;
use k256::PublicKey;

// Live testnet deployments (see @opaquecash/deployments).
const SEPOLIA_ANNOUNCER: &str = "0x840f72249A8bF6F10b0eB64412E315efBD730865";
const SEPOLIA_UAB_RECEIVER: &str = "0x9eF189f7a263F870Cf80f9A89d1349A6AF7b15cF";
const DEVNET_ANNOUNCER: &str = "HGFn2fH7bVQ5cSuiG52NjzN9m11YrB3FZUfoN9b9A5jf";
const DEVNET_UAB_RECEIVER: &str = "7d4Sbmmpy954JwSNdjwf31pgbeWUQqwpgNdte5iy3vuM";

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn key_bytes(env: &str, default: u8) -> Vec<u8> {
    std::env::var(env)
        .ok()
        .and_then(|v| hex::decode(v.trim_start_matches("0x")).ok())
        .unwrap_or_else(|| vec![default; 32])
}

fn main() {
    let eth_rpc = env_or("SEPOLIA_RPC_URL", "https://ethereum-sepolia-rpc.publicnode.com");
    let sol_rpc = env_or("SOLANA_RPC_URL", "https://api.devnet.solana.com");

    // Recipient keys: viewing private key + spending PUBLIC key (watch-only capable).
    let viewing_key = key_bytes("VIEWING_KEY", 0xAA);
    let spend_pubkey = std::env::var("SPENDING_PUBKEY")
        .ok()
        .and_then(|v| hex::decode(v.trim_start_matches("0x")).ok())
        .unwrap_or_else(|| {
            let spend_priv = SigningKey::from_slice(&[0xBB; 32]).unwrap();
            PublicKey::from(spend_priv.verifying_key())
                .to_sec1_bytes()
                .to_vec()
        });
    let scanner = UniversalScanner::new(&viewing_key, &spend_pubkey).expect("valid keys");

    // Sepolia: scan the last ~20k blocks (public RPCs reject huge log ranges).
    let head: serde_json::Value = ureq::post(&eth_rpc)
        .send_json(serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []
        }))
        .expect("eth_blockNumber")
        .into_json()
        .expect("eth_blockNumber body");
    let head = u64::from_str_radix(
        head["result"].as_str().unwrap_or("0x0").trim_start_matches("0x"),
        16,
    )
    .unwrap_or(0);
    let eth_cursor = head.saturating_sub(20_000);

    let ethereum = EthereumAdapter::new(&eth_rpc, SEPOLIA_ANNOUNCER)
        .with_uab_receiver(SEPOLIA_UAB_RECEIVER);
    let solana = SolanaAdapter::new(&sol_rpc, DEVNET_ANNOUNCER)
        .with_uab_receiver(DEVNET_UAB_RECEIVER)
        .with_limit(25);

    // Per-adapter fetch (different cursors), then the shared ownership loop.
    let mut all = Vec::new();
    for (adapter, cursor) in [
        (&ethereum as &dyn DynChainAdapter, eth_cursor),
        (&solana as &dyn DynChainAdapter, 0),
    ] {
        match adapter.fetch_announcements_dyn(cursor) {
            Ok(anns) => {
                println!("{:>9}: fetched {} announcement(s)", adapter.name(), anns.len());
                all.extend(anns);
            }
            Err(e) => eprintln!("{:>9}: {e}", adapter.name()),
        }
    }
    let owned = scanner.filter_owned(&all);
    println!("    owned: {} announcement(s)", owned.len());
    for ann in owned {
        println!("  -> chain {} {}", ann.chain_id, ann.stealth_address);
    }
}
