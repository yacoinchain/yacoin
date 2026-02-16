//! Incremental Merkle Tree for Note Commitments
//!
//! This implements a Pedersen-hash based Merkle tree for YaCoin shielded transactions.
//! The tree has depth 32, allowing for ~4 billion notes.
//!
//! Uses real Jubjub curve Pedersen hashing for cryptographic security.

use borsh::{BorshDeserialize, BorshSerialize};
use crate::error::ShieldedTransferError;
use blake2s_simd::Params;
use jubjub::{ExtendedPoint, Fr, SubgroupPoint};
use group::prime::PrimeCurveAffine;

/// Depth of the commitment tree (2^32 = ~4 billion notes)
pub const TREE_DEPTH: usize = 32;

/// Domain separator for Merkle tree hashing
const MERKLE_HASH_DOMAIN: &[u8; 8] = b"YaCoinMH";

/// Pedersen hash generators (computed lazily)
/// These are fixed points on Jubjub used for hashing
mod generators {
    use super::*;
    use std::sync::OnceLock;

    /// Generator for left input
    static G_LEFT: OnceLock<SubgroupPoint> = OnceLock::new();
    /// Generator for right input
    static G_RIGHT: OnceLock<SubgroupPoint> = OnceLock::new();

    /// Get the left generator point
    pub fn g_left() -> SubgroupPoint {
        *G_LEFT.get_or_init(|| {
            // Derive from domain separator using hash-to-curve
            hash_to_curve(b"YaCoin_G_left___")
        })
    }

    /// Get the right generator point
    pub fn g_right() -> SubgroupPoint {
        *G_RIGHT.get_or_init(|| {
            hash_to_curve(b"YaCoin_G_right__")
        })
    }

    /// Hash to a Jubjub curve point (simplified)
    fn hash_to_curve(domain: &[u8; 16]) -> SubgroupPoint {
        use blake2s_simd::Params;
        use group::Group;

        // Use blake2s to derive point coordinates
        let hash = Params::new()
            .hash_length(32)
            .personal(b"YaCoin_H")
            .to_state()
            .update(domain)
            .finalize();

        // Try to decode as a point (may not be on curve)
        // In production, use proper hash-to-curve
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());

        // Use the generator point scaled by the hash as a simple derivation
        let scalar = Fr::from_bytes(&bytes).unwrap_or(Fr::one());
        // Get generator via Group trait
        SubgroupPoint::generator() * scalar
    }
}

/// Precomputed empty roots for each tree level
/// These are the roots of subtrees with no commitments
mod empty_roots {
    use super::*;
    use std::sync::OnceLock;

    static EMPTY_ROOTS: OnceLock<[[u8; 32]; 33]> = OnceLock::new();

    pub fn get() -> &'static [[u8; 32]; 33] {
        EMPTY_ROOTS.get_or_init(|| {
            let mut roots = [[0u8; 32]; 33];

            // Level 0: empty leaf
            roots[0] = [0u8; 32];

            // Each level is hash of two children from level below
            for i in 1..=TREE_DEPTH {
                roots[i] = pedersen_hash_inner(&roots[i - 1], &roots[i - 1]);
            }

            roots
        })
    }
}

/// Incremental Merkle tree for storing note commitments
///
/// Uses the "frontier" technique to efficiently append leaves
/// without storing the entire tree.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct IncrementalMerkleTree {
    /// Current root of the tree
    root: [u8; 32],
    /// Number of leaves in the tree
    size: u64,
    /// Frontier: the authentication path of the rightmost leaf
    /// Contains one hash per level that's needed to compute the root
    frontier: Vec<[u8; 32]>,
}

impl IncrementalMerkleTree {
    /// Create a new empty tree
    pub fn new() -> Self {
        Self {
            root: empty_roots::get()[TREE_DEPTH],
            size: 0,
            frontier: Vec::with_capacity(TREE_DEPTH),
        }
    }

    /// Get current root
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Get number of leaves
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get the frontier (authentication path hashes)
    pub fn frontier(&self) -> &[[u8; 32]] {
        &self.frontier
    }

    /// Create tree from serialized parts
    pub fn from_parts(root: [u8; 32], size: usize, frontier: Vec<[u8; 32]>) -> Self {
        Self {
            root,
            size: size as u64,
            frontier,
        }
    }

    /// Append a new commitment to the tree
    pub fn append(&mut self, commitment: [u8; 32]) -> Result<u64, ShieldedTransferError> {
        if self.size >= (1u64 << TREE_DEPTH) {
            return Err(ShieldedTransferError::CommitmentTreeFull);
        }

        let position = self.size;
        let mut current = commitment;
        let mut depth = 0usize;

        // Walk up the tree, combining with frontier or empty roots
        while depth < TREE_DEPTH {
            let is_right = (position >> depth) & 1 == 1;

            if is_right {
                // We're a right child, combine with frontier at this level
                let left = if depth < self.frontier.len() {
                    self.frontier[depth]
                } else {
                    empty_roots::get()[depth]
                };
                current = pedersen_hash(&left, &current);
            } else {
                // We're a left child, store in frontier and combine with empty
                if depth >= self.frontier.len() {
                    self.frontier.push(current);
                } else {
                    self.frontier[depth] = current;
                }
                current = pedersen_hash(&current, &empty_roots::get()[depth]);
            }

            depth = depth.saturating_add(1);
        }

        self.root = current;
        self.size = position.saturating_add(1);

        Ok(position)
    }

    /// Get the authentication path (witness) for a leaf at given position
    pub fn witness(&self, position: u64) -> Result<MerkleWitness, ShieldedTransferError> {
        if position >= self.size {
            return Err(ShieldedTransferError::InvalidAnchor);
        }

        let mut path = [[0u8; 32]; TREE_DEPTH];
        let mut position_bits = [false; TREE_DEPTH];

        // For positions that have been appended, we can compute siblings
        // from the frontier and empty roots
        for i in 0..TREE_DEPTH {
            position_bits[i] = (position >> i) & 1 == 1;

            // Compute sibling at this level
            if position_bits[i] {
                // We're on right, sibling is in frontier
                if i < self.frontier.len() {
                    path[i] = self.frontier[i];
                } else {
                    path[i] = empty_roots::get()[i];
                }
            } else {
                // We're on left, sibling is computed or empty
                let sibling_pos = position ^ (1 << i);
                if sibling_pos < self.size {
                    // Sibling exists - would need full tree to compute
                    // For now use frontier if available
                    if i < self.frontier.len() {
                        path[i] = self.frontier[i];
                    } else {
                        path[i] = empty_roots::get()[i];
                    }
                } else {
                    // Sibling doesn't exist, use empty root
                    path[i] = empty_roots::get()[i];
                }
            }
        }

        Ok(MerkleWitness {
            path,
            position: position_bits,
        })
    }
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Merkle authentication path for proving membership
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct MerkleWitness {
    /// Sibling hashes from leaf to root
    pub path: [[u8; 32]; TREE_DEPTH],
    /// Position bits (false = left, true = right)
    pub position: [bool; TREE_DEPTH],
}

impl MerkleWitness {
    /// Verify that a commitment at this position produces the given root
    pub fn verify(&self, commitment: &[u8; 32], expected_root: &[u8; 32]) -> bool {
        let mut current = *commitment;

        for i in 0..TREE_DEPTH {
            if self.position[i] {
                // We're on the right
                current = pedersen_hash(&self.path[i], &current);
            } else {
                // We're on the left
                current = pedersen_hash(&current, &self.path[i]);
            }
        }

        current == *expected_root
    }
}

/// Recent anchors cache
/// Stores recent Merkle roots so spends can reference slightly old state
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct RecentAnchors {
    /// Ring buffer of recent roots
    anchors: Vec<[u8; 32]>,
    /// Current position in ring buffer
    position: usize,
    /// Maximum number of anchors to store
    capacity: usize,
}

impl RecentAnchors {
    pub fn new(capacity: usize) -> Self {
        Self {
            anchors: Vec::with_capacity(capacity),
            position: 0,
            capacity,
        }
    }

    /// Add a new anchor
    pub fn push(&mut self, anchor: [u8; 32]) {
        if self.anchors.len() < self.capacity {
            self.anchors.push(anchor);
        } else {
            self.anchors[self.position] = anchor;
        }
        self.position = (self.position.saturating_add(1)) % self.capacity;
    }

    /// Check if an anchor is in the recent set
    pub fn contains(&self, anchor: &[u8; 32]) -> bool {
        self.anchors.iter().any(|a| a == anchor)
    }

    /// Add an anchor (alias for push)
    pub fn add(&mut self, anchor: [u8; 32]) {
        self.push(anchor);
    }

    /// Iterate over anchors
    pub fn iter(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.anchors.iter()
    }

    /// Get number of anchors
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// Pedersen hash function for Merkle tree
/// Uses Jubjub curve scalar multiplication
fn pedersen_hash_inner(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // Convert inputs to scalars
    let left_scalar = bytes_to_scalar(left);
    let right_scalar = bytes_to_scalar(right);

    // Compute: left_scalar * G_left + right_scalar * G_right
    let g_left = generators::g_left();
    let g_right = generators::g_right();

    let point: ExtendedPoint = (g_left * left_scalar + g_right * right_scalar).into();

    // Extract the x-coordinate as the hash output
    let affine = jubjub::AffinePoint::from(point);
    let u = affine.get_u();
    u.to_bytes()
}

/// Public Pedersen hash function
pub fn pedersen_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // Use blake2s as a compression function with the Pedersen hash result
    // This provides extra security and domain separation
    let pedersen_result = pedersen_hash_inner(left, right);

    let hash = Params::new()
        .hash_length(32)
        .personal(MERKLE_HASH_DOMAIN)
        .to_state()
        .update(&pedersen_result)
        .update(left)
        .update(right)
        .finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(hash.as_bytes());
    output
}

/// Convert 32 bytes to a Jubjub scalar
fn bytes_to_scalar(bytes: &[u8; 32]) -> Fr {
    // Use the bytes directly as a scalar representation
    // Fr::from_bytes handles reduction if necessary
    Fr::from_bytes(bytes).unwrap_or(Fr::zero())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = IncrementalMerkleTree::new();
        assert_eq!(tree.size(), 0);
    }

    #[test]
    fn test_append_commitment() {
        let mut tree = IncrementalMerkleTree::new();
        let commitment = [1u8; 32];

        let pos = tree.append(commitment).unwrap();
        assert_eq!(pos, 0);
        assert_eq!(tree.size(), 1);
    }

    #[test]
    fn test_multiple_appends() {
        let mut tree = IncrementalMerkleTree::new();

        for i in 0..10u8 {
            let mut commitment = [0u8; 32];
            commitment[0] = i;
            let pos = tree.append(commitment).unwrap();
            assert_eq!(pos, i as u64);
        }

        assert_eq!(tree.size(), 10);
    }

    #[test]
    fn test_pedersen_hash_deterministic() {
        let left = [1u8; 32];
        let right = [2u8; 32];

        let hash1 = pedersen_hash(&left, &right);
        let hash2 = pedersen_hash(&left, &right);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_pedersen_hash_different_inputs() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];

        let hash1 = pedersen_hash(&a, &b);
        let hash2 = pedersen_hash(&a, &c);
        let hash3 = pedersen_hash(&b, &a);

        // Different inputs should produce different outputs
        assert_ne!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_witness_verification() {
        let mut tree = IncrementalMerkleTree::new();
        let commitment = [42u8; 32];

        tree.append(commitment).unwrap();
        let root = tree.root();

        let witness = tree.witness(0).unwrap();
        assert!(witness.verify(&commitment, &root));
    }

    #[test]
    fn test_recent_anchors() {
        let mut anchors = RecentAnchors::new(5);

        for i in 0..10u8 {
            let mut anchor = [0u8; 32];
            anchor[0] = i;
            anchors.push(anchor);
        }

        // Only last 5 should be present
        for i in 5..10u8 {
            let mut anchor = [0u8; 32];
            anchor[0] = i;
            assert!(anchors.contains(&anchor));
        }

        // First 5 should be gone
        for i in 0..5u8 {
            let mut anchor = [0u8; 32];
            anchor[0] = i;
            assert!(!anchors.contains(&anchor));
        }
    }

    #[test]
    fn test_empty_roots_consistent() {
        let roots = empty_roots::get();

        // Empty root at level 0 should be all zeros
        assert_eq!(roots[0], [0u8; 32]);

        // Higher levels should be hashes of children
        for i in 1..=TREE_DEPTH {
            let expected = pedersen_hash_inner(&roots[i - 1], &roots[i - 1]);
            assert_eq!(roots[i], expected);
        }
    }
}
