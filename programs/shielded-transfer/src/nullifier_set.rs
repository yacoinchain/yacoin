//! Nullifier Set for Double-Spend Prevention
//!
//! Each shielded note has a unique nullifier derived from the note and spending key.
//! Once a note is spent, its nullifier is added to this set.
//! Any attempt to spend with the same nullifier is rejected.

use borsh::{BorshDeserialize, BorshSerialize};
use crate::error::ShieldedTransferError;

/// Size of a nullifier in bytes
pub const NULLIFIER_SIZE: usize = 32;

/// Maximum nullifiers per account (to bound account size)
pub const MAX_NULLIFIERS_PER_ACCOUNT: usize = 10_000;

/// Nullifier set stored on-chain
///
/// Uses a sorted list for efficient binary search lookups
#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct NullifierSet {
    /// Sorted list of nullifiers for binary search
    nullifiers: Vec<[u8; NULLIFIER_SIZE]>,
    /// Number of nullifiers
    count: u64,
}

impl NullifierSet {
    /// Create a new empty nullifier set
    pub fn new() -> Self {
        Self {
            nullifiers: Vec::new(),
            count: 0,
        }
    }

    /// Create with specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            nullifiers: Vec::with_capacity(capacity),
            count: 0,
        }
    }

    /// Check if a nullifier has been spent
    pub fn contains(&self, nullifier: &[u8; NULLIFIER_SIZE]) -> bool {
        self.nullifiers.binary_search(nullifier).is_ok()
    }

    /// Add a nullifier to the set
    ///
    /// Returns error if nullifier already exists (double-spend) or set is full
    pub fn insert(&mut self, nullifier: [u8; NULLIFIER_SIZE]) -> Result<(), ShieldedTransferError> {
        if self.count >= MAX_NULLIFIERS_PER_ACCOUNT as u64 {
            return Err(ShieldedTransferError::NullifierSetFull);
        }

        // Check for double-spend
        match self.nullifiers.binary_search(&nullifier) {
            Ok(_) => {
                // Already exists - double spend attempt!
                Err(ShieldedTransferError::NullifierAlreadySpent)
            }
            Err(pos) => {
                // Insert at correct position to maintain sorted order
                self.nullifiers.insert(pos, nullifier);
                self.count = self.count.saturating_add(1);
                Ok(())
            }
        }
    }

    /// Get the count of nullifiers
    pub fn len(&self) -> u64 {
        self.count
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over nullifiers
    pub fn iter(&self) -> impl Iterator<Item = &[u8; NULLIFIER_SIZE]> {
        self.nullifiers.iter()
    }
}

/// Partitioned nullifier set for scalability
/// Splits nullifiers across multiple accounts based on prefix
#[derive(Clone, Debug)]
pub struct PartitionedNullifierSet {
    /// Number of partitions (accounts)
    pub num_partitions: u8,
}

impl PartitionedNullifierSet {
    /// Create a new partitioned set
    pub fn new(num_partitions: u8) -> Self {
        Self { num_partitions }
    }

    /// Get partition index for a nullifier
    pub fn partition_for(&self, nullifier: &[u8; NULLIFIER_SIZE]) -> u8 {
        // Use first byte of nullifier as partition key
        nullifier[0] % self.num_partitions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_set() {
        let set = NullifierSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_insert_and_contains() {
        let mut set = NullifierSet::new();
        let nullifier = [42u8; NULLIFIER_SIZE];

        assert!(!set.contains(&nullifier));
        set.insert(nullifier).unwrap();
        assert!(set.contains(&nullifier));
    }

    #[test]
    fn test_double_spend_prevention() {
        let mut set = NullifierSet::new();
        let nullifier = [42u8; NULLIFIER_SIZE];

        set.insert(nullifier).unwrap();

        // Second insert should fail (double-spend)
        let result = set.insert(nullifier);
        assert!(matches!(result, Err(ShieldedTransferError::NullifierAlreadySpent)));
    }

    #[test]
    fn test_multiple_nullifiers() {
        let mut set = NullifierSet::new();

        for i in 0..100u8 {
            let mut nullifier = [0u8; NULLIFIER_SIZE];
            nullifier[0] = i;
            set.insert(nullifier).unwrap();
        }

        assert_eq!(set.len(), 100);

        // Verify all are contained
        for i in 0..100u8 {
            let mut nullifier = [0u8; NULLIFIER_SIZE];
            nullifier[0] = i;
            assert!(set.contains(&nullifier));
        }
    }

    #[test]
    fn test_partitioning() {
        let partitioned = PartitionedNullifierSet::new(16);

        // Check distribution
        let mut counts = [0u32; 16];
        for i in 0..=255u8 {
            let mut nullifier = [0u8; NULLIFIER_SIZE];
            nullifier[0] = i;
            let partition = partitioned.partition_for(&nullifier);
            counts[partition as usize] = counts[partition as usize].saturating_add(1);
        }

        // Each partition should have 16 items
        for count in counts.iter() {
            assert_eq!(*count, 16);
        }
    }
}
