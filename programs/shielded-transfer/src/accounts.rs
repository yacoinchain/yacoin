//! Account management for shielded transfer program
//!
//! This module handles PDA derivation and state serialization for:
//! - Shielded pool state
//! - Commitment tree
//! - Nullifier set
//! - Recent anchors

use borsh::{BorshDeserialize, BorshSerialize};
use solana_pubkey::Pubkey;

use crate::{
    commitment_tree::{IncrementalMerkleTree, RecentAnchors, TREE_DEPTH},
    error::ShieldedTransferError,
    nullifier_set::NullifierSet,
    state::ShieldedPoolState,
};

/// Re-export tree depth as MERKLE_DEPTH for clarity
pub const MERKLE_DEPTH: usize = TREE_DEPTH;

/// Seeds for PDA derivation
pub const POOL_SEED: &[u8] = b"shielded_pool";
pub const TREE_SEED: &[u8] = b"commitment_tree";
pub const NULLIFIER_SEED: &[u8] = b"nullifier_set";
pub const ANCHOR_SEED: &[u8] = b"recent_anchors";

/// Maximum nullifiers stored on-chain (use bloom filter for overflow)
pub const MAX_NULLIFIERS: usize = 100_000;

/// Maximum recent anchors
pub const MAX_RECENT_ANCHORS: usize = 100;

/// Derive the pool state PDA
pub fn derive_pool_address(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[POOL_SEED], program_id)
}

/// Derive the commitment tree PDA
pub fn derive_tree_address(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[TREE_SEED], program_id)
}

/// Derive the nullifier set PDA
pub fn derive_nullifier_address(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[NULLIFIER_SEED], program_id)
}

/// Derive the recent anchors PDA
pub fn derive_anchor_address(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ANCHOR_SEED], program_id)
}

/// Serializable commitment tree state
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct CommitmentTreeAccount {
    /// Current root
    pub root: [u8; 32],
    /// Number of leaves (commitments)
    pub size: u64,
    /// Frontier hashes for incremental updates
    pub frontier: Vec<[u8; 32]>,
}

impl CommitmentTreeAccount {
    /// Size estimate for account allocation
    pub const SIZE: usize = 32 + 8 + (MERKLE_DEPTH * 32) + 64; // ~1.2KB

    /// Create from IncrementalMerkleTree
    pub fn from_tree(tree: &IncrementalMerkleTree) -> Self {
        Self {
            root: tree.root(),
            size: tree.size(),
            frontier: tree.frontier().to_vec(),
        }
    }

    /// Convert to IncrementalMerkleTree
    pub fn to_tree(&self) -> IncrementalMerkleTree {
        IncrementalMerkleTree::from_parts(
            self.root,
            self.size as usize,
            self.frontier.clone(),
        )
    }
}

/// Serializable nullifier set
/// Uses a compact representation with optional bloom filter for scalability
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct NullifierSetAccount {
    /// Number of nullifiers
    pub count: u64,
    /// Stored nullifiers (for small sets)
    pub nullifiers: Vec<[u8; 32]>,
    /// Bloom filter for fast negative lookups (when set grows large)
    pub bloom_filter: Option<BloomFilter>,
}

impl NullifierSetAccount {
    /// Size estimate (grows with usage)
    pub fn size(&self) -> usize {
        8 + (self.nullifiers.len() * 32) + self.bloom_filter.as_ref().map_or(0, |b| b.size())
    }

    /// Create from NullifierSet
    pub fn from_set(set: &NullifierSet) -> Self {
        let nullifiers: Vec<[u8; 32]> = set.iter().copied().collect();
        Self {
            count: nullifiers.len() as u64,
            nullifiers,
            bloom_filter: None,
        }
    }

    /// Convert to NullifierSet
    pub fn to_set(&self) -> NullifierSet {
        let mut set = NullifierSet::new();
        for nf in &self.nullifiers {
            let _ = set.insert(*nf);
        }
        set
    }

    /// Check if nullifier exists (fast path using bloom filter)
    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        // Fast negative check with bloom filter
        if let Some(bloom) = &self.bloom_filter {
            if !bloom.may_contain(nullifier) {
                return false;
            }
        }
        // Full check in nullifier list
        self.nullifiers.iter().any(|nf| nf == nullifier)
    }

    /// Insert a nullifier
    pub fn insert(&mut self, nullifier: [u8; 32]) -> Result<(), ShieldedTransferError> {
        if self.contains(&nullifier) {
            return Err(ShieldedTransferError::NullifierAlreadySpent);
        }

        self.nullifiers.push(nullifier);
        self.count += 1;

        // Update bloom filter if it exists
        if let Some(bloom) = &mut self.bloom_filter {
            bloom.insert(&nullifier);
        }

        // Create bloom filter when list gets large
        if self.bloom_filter.is_none() && self.count > 1000 {
            let mut bloom = BloomFilter::new(10_000);
            for nf in &self.nullifiers {
                bloom.insert(nf);
            }
            self.bloom_filter = Some(bloom);
        }

        Ok(())
    }
}

/// Simple bloom filter for probabilistic nullifier lookup
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct BloomFilter {
    /// Bit array
    bits: Vec<u8>,
    /// Number of hash functions
    num_hashes: u8,
}

impl BloomFilter {
    /// Create new bloom filter
    pub fn new(size_bits: usize) -> Self {
        Self {
            bits: vec![0u8; (size_bits + 7) / 8],
            num_hashes: 7, // ~0.01 false positive rate
        }
    }

    /// Size in bytes
    pub fn size(&self) -> usize {
        self.bits.len() + 1
    }

    /// Insert element
    pub fn insert(&mut self, data: &[u8; 32]) {
        for i in 0..self.num_hashes {
            let hash = self.hash(data, i);
            let bit_index = hash % (self.bits.len() * 8);
            self.bits[bit_index / 8] |= 1 << (bit_index % 8);
        }
    }

    /// Check if element may be present
    pub fn may_contain(&self, data: &[u8; 32]) -> bool {
        for i in 0..self.num_hashes {
            let hash = self.hash(data, i);
            let bit_index = hash % (self.bits.len() * 8);
            if self.bits[bit_index / 8] & (1 << (bit_index % 8)) == 0 {
                return false;
            }
        }
        true
    }

    /// Hash function
    fn hash(&self, data: &[u8; 32], index: u8) -> usize {
        use blake2b_simd::Params;
        let hash = Params::new()
            .hash_length(8)
            .personal(b"YaCoin_bloom____")
            .to_state()
            .update(data)
            .update(&[index])
            .finalize();
        u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap()) as usize
    }
}

/// Serializable recent anchors
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct RecentAnchorsAccount {
    /// Circular buffer of recent roots
    pub anchors: Vec<[u8; 32]>,
    /// Current write position
    pub position: u64,
    /// Max anchors to store
    pub max_size: u64,
}

impl RecentAnchorsAccount {
    /// Size estimate
    pub const SIZE: usize = (MAX_RECENT_ANCHORS * 32) + 16;

    /// Create from RecentAnchors
    pub fn from_anchors(anchors: &RecentAnchors) -> Self {
        Self {
            anchors: anchors.iter().copied().collect(),
            position: anchors.len() as u64,
            max_size: MAX_RECENT_ANCHORS as u64,
        }
    }

    /// Convert to RecentAnchors
    pub fn to_anchors(&self) -> RecentAnchors {
        let mut recent = RecentAnchors::new(self.max_size as usize);
        for anchor in &self.anchors {
            recent.add(*anchor);
        }
        recent
    }

    /// Check if anchor is valid
    pub fn contains(&self, anchor: &[u8; 32]) -> bool {
        self.anchors.iter().any(|a| a == anchor)
    }

    /// Add new anchor
    pub fn add(&mut self, anchor: [u8; 32]) {
        if self.anchors.len() < self.max_size as usize {
            self.anchors.push(anchor);
        } else {
            let pos = (self.position as usize) % self.anchors.len();
            self.anchors[pos] = anchor;
        }
        self.position += 1;
    }
}

/// Length prefix size (4 bytes for u32)
const LENGTH_PREFIX_SIZE: usize = 4;

/// Load pool state from account data (length-prefixed)
pub fn load_pool_state(data: &[u8]) -> Result<ShieldedPoolState, ShieldedTransferError> {
    if data.len() < LENGTH_PREFIX_SIZE {
        return Err(ShieldedTransferError::InvalidAccountData);
    }
    let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    if len == 0 || data.len() < LENGTH_PREFIX_SIZE + len {
        return Err(ShieldedTransferError::InvalidAccountData);
    }
    ShieldedPoolState::try_from_slice(&data[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + len])
        .map_err(|_| ShieldedTransferError::InvalidAccountData)
}

/// Save pool state to account data (length-prefixed)
pub fn save_pool_state(state: &ShieldedPoolState, data: &mut [u8]) -> Result<(), ShieldedTransferError> {
    let serialized = borsh::to_vec(state)
        .map_err(|_| ShieldedTransferError::SerializationError)?;

    let total_len = LENGTH_PREFIX_SIZE + serialized.len();
    if total_len > data.len() {
        return Err(ShieldedTransferError::AccountTooSmall);
    }

    // Write length prefix
    data[..4].copy_from_slice(&(serialized.len() as u32).to_le_bytes());
    // Write data
    data[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + serialized.len()].copy_from_slice(&serialized);
    Ok(())
}

/// Load commitment tree from account data (length-prefixed)
pub fn load_commitment_tree(data: &[u8]) -> Result<IncrementalMerkleTree, ShieldedTransferError> {
    if data.len() < LENGTH_PREFIX_SIZE {
        return Err(ShieldedTransferError::InvalidAccountData);
    }
    let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    if len == 0 || data.len() < LENGTH_PREFIX_SIZE + len {
        return Err(ShieldedTransferError::InvalidAccountData);
    }
    let account = CommitmentTreeAccount::try_from_slice(&data[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + len])
        .map_err(|_| ShieldedTransferError::InvalidAccountData)?;
    Ok(account.to_tree())
}

/// Save commitment tree to account data (length-prefixed)
pub fn save_commitment_tree(tree: &IncrementalMerkleTree, data: &mut [u8]) -> Result<(), ShieldedTransferError> {
    let account = CommitmentTreeAccount::from_tree(tree);
    let serialized = borsh::to_vec(&account)
        .map_err(|_| ShieldedTransferError::SerializationError)?;

    let total_len = LENGTH_PREFIX_SIZE + serialized.len();
    if total_len > data.len() {
        return Err(ShieldedTransferError::AccountTooSmall);
    }

    data[..4].copy_from_slice(&(serialized.len() as u32).to_le_bytes());
    data[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + serialized.len()].copy_from_slice(&serialized);
    Ok(())
}

/// Load nullifier set from account data (length-prefixed)
pub fn load_nullifier_set(data: &[u8]) -> Result<NullifierSetAccount, ShieldedTransferError> {
    if data.len() < LENGTH_PREFIX_SIZE {
        return Err(ShieldedTransferError::InvalidAccountData);
    }
    let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    if len == 0 || data.len() < LENGTH_PREFIX_SIZE + len {
        return Err(ShieldedTransferError::InvalidAccountData);
    }
    NullifierSetAccount::try_from_slice(&data[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + len])
        .map_err(|_| ShieldedTransferError::InvalidAccountData)
}

/// Save nullifier set to account data (length-prefixed)
pub fn save_nullifier_set(set: &NullifierSetAccount, data: &mut [u8]) -> Result<(), ShieldedTransferError> {
    let serialized = borsh::to_vec(set)
        .map_err(|_| ShieldedTransferError::SerializationError)?;

    let total_len = LENGTH_PREFIX_SIZE + serialized.len();
    if total_len > data.len() {
        return Err(ShieldedTransferError::AccountTooSmall);
    }

    data[..4].copy_from_slice(&(serialized.len() as u32).to_le_bytes());
    data[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + serialized.len()].copy_from_slice(&serialized);
    Ok(())
}

/// Load recent anchors from account data (length-prefixed)
pub fn load_recent_anchors(data: &[u8]) -> Result<RecentAnchorsAccount, ShieldedTransferError> {
    if data.len() < LENGTH_PREFIX_SIZE {
        return Err(ShieldedTransferError::InvalidAccountData);
    }
    let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    if len == 0 || data.len() < LENGTH_PREFIX_SIZE + len {
        return Err(ShieldedTransferError::InvalidAccountData);
    }
    RecentAnchorsAccount::try_from_slice(&data[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + len])
        .map_err(|_| ShieldedTransferError::InvalidAccountData)
}

/// Save recent anchors to account data (length-prefixed)
pub fn save_recent_anchors(anchors: &RecentAnchorsAccount, data: &mut [u8]) -> Result<(), ShieldedTransferError> {
    let serialized = borsh::to_vec(anchors)
        .map_err(|_| ShieldedTransferError::SerializationError)?;

    let total_len = LENGTH_PREFIX_SIZE + serialized.len();
    if total_len > data.len() {
        return Err(ShieldedTransferError::AccountTooSmall);
    }

    data[..4].copy_from_slice(&(serialized.len() as u32).to_le_bytes());
    data[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + serialized.len()].copy_from_slice(&serialized);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pda_derivation() {
        let program_id = Pubkey::new_unique();
        let (pool_addr, pool_bump) = derive_pool_address(&program_id);
        let (tree_addr, tree_bump) = derive_tree_address(&program_id);

        // Addresses should be different
        assert_ne!(pool_addr, tree_addr);

        // Bumps should be valid (non-zero typically)
        assert!(pool_bump > 0 || tree_bump > 0);
    }

    #[test]
    fn test_nullifier_set_bloom() {
        let mut set = NullifierSetAccount {
            count: 0,
            nullifiers: Vec::new(),
            bloom_filter: None,
        };

        // Insert nullifiers
        for i in 0..100 {
            let mut nf = [0u8; 32];
            nf[0] = i as u8;
            set.insert(nf).unwrap();
        }

        // Should find existing nullifiers
        let mut nf = [0u8; 32];
        nf[0] = 50;
        assert!(set.contains(&nf));

        // Should not find non-existent
        nf[0] = 200;
        assert!(!set.contains(&nf));

        // Double-insert should fail
        nf[0] = 50;
        assert!(set.insert(nf).is_err());
    }

    #[test]
    fn test_commitment_tree_roundtrip() {
        let mut tree = IncrementalMerkleTree::new();
        tree.append([1u8; 32]).unwrap();
        tree.append([2u8; 32]).unwrap();

        let account = CommitmentTreeAccount::from_tree(&tree);
        let restored = account.to_tree();

        assert_eq!(tree.root(), restored.root());
        assert_eq!(tree.size(), restored.size());
    }
}
