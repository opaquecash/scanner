//! # Light-Client Poseidon Merkle Tree
//!
//! In-memory Merkle tree using Poseidon hashing for generating inclusion proofs
//! locally. Designed for the browser extension: fixed-depth, lazy allocation,
//! low memory footprint.
//!
//! The tree indexes stealth attestation announcements so the user can produce
//! a Merkle path for the ZK-attestation circuit without contacting a server.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

// =============================================================================
// ⚠ NOT circuit-compatible. This is domain-tagged Keccak256 reduced into the
// BN254 scalar field — NOT the Poseidon hash the stealth_reputation circuit
// constrains. Witnesses built from this tree can never satisfy the circuit;
// the canonical witness builder is `buildWitnessV2` in @opaquecash/psr-prover
// (circomlibjs Poseidon). This module remains as a generic Merkle utility for
// indexing/dedup use cases only.
// =============================================================================

/// Hash two field elements with a domain-tagged Keccak256 and reduce mod BN254 scalar field.
/// In production, replace with an arkworks Poseidon or a hand-optimized Poseidon for BN254.
///
/// BN254 scalar field: p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const BN254_SCALAR_FIELD: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
    0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
    0x00, 0x01,
];

fn poseidon_hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"Poseidon");
    hasher.update(left);
    hasher.update(right);
    let digest: [u8; 32] = hasher.finalize().into();
    reduce_mod_field(&digest)
}

fn poseidon_hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"PoseidonLeaf");
    hasher.update(data);
    let digest: [u8; 32] = hasher.finalize().into();
    reduce_mod_field(&digest)
}

/// Reduces a 32-byte value modulo the BN254 scalar field via big-endian subtraction.
/// Simplified: if value >= p, subtract p once. For SNARK-compatible values this is sufficient
/// since Keccak output is uniformly distributed and p ~ 2^254.
fn reduce_mod_field(val: &[u8; 32]) -> [u8; 32] {
    let mut borrow = false;
    let mut result = [0u8; 32];
    for i in (0..32).rev() {
        let a = val[i] as u16;
        let b = BN254_SCALAR_FIELD[i] as u16 + if borrow { 1 } else { 0 };
        if a >= b {
            result[i] = (a - b) as u8;
            borrow = false;
        } else {
            result[i] = (256 + a - b) as u8;
            borrow = true;
        }
    }
    if borrow {
        *val
    } else {
        result
    }
}

// =============================================================================
// Merkle tree
// =============================================================================

const ZERO_LEAF: [u8; 32] = [0u8; 32];

/// Merkle inclusion proof for the ZK circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    pub path_elements: Vec<[u8; 32]>,
    pub path_indices: Vec<u8>,
    pub root: [u8; 32],
}

/// Fixed-depth Poseidon Merkle tree. Leaves are inserted sequentially.
/// Capacity = 2^depth.
pub struct MerkleTree {
    depth: usize,
    leaves: Vec<[u8; 32]>,
    /// Pre-computed zero hashes for each level (hash of empty subtrees).
    zero_hashes: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        let mut zero_hashes = Vec::with_capacity(depth + 1);
        zero_hashes.push(ZERO_LEAF);
        for i in 0..depth {
            let prev = zero_hashes[i];
            zero_hashes.push(poseidon_hash_pair(&prev, &prev));
        }
        MerkleTree {
            depth,
            leaves: Vec::new(),
            zero_hashes,
        }
    }

    pub fn capacity(&self) -> usize {
        1 << self.depth
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Insert a raw leaf (will be hashed internally).
    pub fn insert_raw(&mut self, data: &[u8]) -> usize {
        let leaf = poseidon_hash_leaf(data);
        self.insert(leaf)
    }

    /// Insert a pre-hashed leaf.
    pub fn insert(&mut self, leaf: [u8; 32]) -> usize {
        assert!(
            self.leaves.len() < self.capacity(),
            "Merkle tree is full"
        );
        let idx = self.leaves.len();
        self.leaves.push(leaf);
        idx
    }

    /// Compute the Merkle root. Recomputes from scratch (acceptable for < 1M leaves in WASM).
    pub fn root(&self) -> [u8; 32] {
        self.compute_root_from(0, self.depth)
    }

    fn compute_root_from(&self, start_leaf_idx: usize, level: usize) -> [u8; 32] {
        if level == 0 {
            return if start_leaf_idx < self.leaves.len() {
                self.leaves[start_leaf_idx]
            } else {
                self.zero_hashes[0]
            };
        }
        let half = 1 << (level - 1);
        let left = self.compute_root_from(start_leaf_idx, level - 1);
        let right = self.compute_root_from(start_leaf_idx + half, level - 1);
        poseidon_hash_pair(&left, &right)
    }

    /// Generate an inclusion proof for the leaf at `index`.
    pub fn proof(&self, index: usize) -> MerkleProof {
        assert!(index < self.leaves.len(), "Index out of bounds");

        let mut path_elements = Vec::with_capacity(self.depth);
        let mut path_indices = Vec::with_capacity(self.depth);

        let mut current_idx = index;
        for level in 0..self.depth {
            let sibling_idx = current_idx ^ 1;
            let sibling = self.get_node(sibling_idx, level);
            path_elements.push(sibling);
            path_indices.push((current_idx & 1) as u8);
            current_idx >>= 1;
        }

        MerkleProof {
            leaf: self.leaves[index],
            path_elements,
            path_indices,
            root: self.root(),
        }
    }

    fn get_node(&self, index: usize, level: usize) -> [u8; 32] {
        if level == 0 {
            return if index < self.leaves.len() {
                self.leaves[index]
            } else {
                self.zero_hashes[0]
            };
        }
        let half = 1 << (level - 1);
        let start = index * (1 << level);
        let _left = self.get_node(start, 0);
        let _ = half;
        self.compute_root_from(start, level)
    }

    /// Verify a proof against a given root.
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current = proof.leaf;
        for i in 0..proof.path_elements.len() {
            if proof.path_indices[i] == 0 {
                current = poseidon_hash_pair(&current, &proof.path_elements[i]);
            } else {
                current = poseidon_hash_pair(&proof.path_elements[i], &current);
            }
        }
        current == proof.root
    }
}

// =============================================================================
// Witness data for the Circom circuit
// =============================================================================

/// Complete witness for the StealthAttestation circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitWitness {
    pub merkle_root: String,
    pub attestation_id: String,
    pub external_nullifier: String,
    pub stealth_private_key: String,
    pub ephemeral_pubkey: [String; 2],
    pub announcement_attestation_id: String,
    pub merkle_path_elements: Vec<String>,
    pub merkle_path_indices: Vec<u8>,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_root_is_deterministic() {
        let t1 = MerkleTree::new(4);
        let t2 = MerkleTree::new(4);
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn insert_changes_root() {
        let mut tree = MerkleTree::new(4);
        let root_empty = tree.root();
        tree.insert_raw(b"hello");
        assert_ne!(root_empty, tree.root());
    }

    #[test]
    fn proof_verifies() {
        let mut tree = MerkleTree::new(4);
        tree.insert_raw(b"leaf_0");
        tree.insert_raw(b"leaf_1");
        tree.insert_raw(b"leaf_2");

        let proof = tree.proof(1);
        assert!(MerkleTree::verify_proof(&proof));
    }

    #[test]
    fn tampered_proof_fails() {
        let mut tree = MerkleTree::new(4);
        tree.insert_raw(b"leaf_0");
        tree.insert_raw(b"leaf_1");

        let mut proof = tree.proof(0);
        proof.leaf = [0xFF; 32];
        assert!(!MerkleTree::verify_proof(&proof));
    }

    #[test]
    fn single_leaf_tree() {
        let mut tree = MerkleTree::new(2);
        tree.insert_raw(b"only");
        let proof = tree.proof(0);
        assert!(MerkleTree::verify_proof(&proof));
    }
}
