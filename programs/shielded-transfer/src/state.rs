//! State structures for the shielded transfer program

use borsh::{BorshDeserialize, BorshSerialize};

/// State of the shielded pool
#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct ShieldedPoolState {
    /// Authority pubkey (stored as 32 bytes)
    pub authority: [u8; 32],
    /// Total shielded value (should always equal commitment tree total)
    pub total_shielded: u64,
    /// Current commitment tree size (number of notes)
    pub commitment_count: u64,
    /// Current nullifier count
    pub nullifier_count: u64,
    /// Is initialized
    pub is_initialized: bool,
}

impl ShieldedPoolState {
    /// Size of the serialized state
    pub const SIZE: usize = 32 + 8 + 8 + 8 + 1; // pubkey + 3 u64s + bool

    /// Create a new pool state
    pub fn new(authority: [u8; 32]) -> Self {
        Self {
            authority,
            total_shielded: 0,
            commitment_count: 0,
            nullifier_count: 0,
            is_initialized: true,
        }
    }

    /// Add shielded value
    pub fn add_shielded(&mut self, amount: u64) -> Result<(), crate::error::ShieldedTransferError> {
        self.total_shielded = self.total_shielded
            .checked_add(amount)
            .ok_or(crate::error::ShieldedTransferError::ArithmeticOverflow)?;
        Ok(())
    }

    /// Remove shielded value
    pub fn remove_shielded(&mut self, amount: u64) -> Result<(), crate::error::ShieldedTransferError> {
        self.total_shielded = self.total_shielded
            .checked_sub(amount)
            .ok_or(crate::error::ShieldedTransferError::InsufficientShieldedBalance)?;
        Ok(())
    }

    /// Increment commitment count
    pub fn increment_commitments(&mut self) -> Result<(), crate::error::ShieldedTransferError> {
        self.commitment_count = self.commitment_count
            .checked_add(1)
            .ok_or(crate::error::ShieldedTransferError::ArithmeticOverflow)?;
        Ok(())
    }

    /// Increment nullifier count
    pub fn increment_nullifiers(&mut self) -> Result<(), crate::error::ShieldedTransferError> {
        self.nullifier_count = self.nullifier_count
            .checked_add(1)
            .ok_or(crate::error::ShieldedTransferError::ArithmeticOverflow)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_state_new() {
        let authority = [1u8; 32];
        let state = ShieldedPoolState::new(authority);
        assert!(state.is_initialized);
        assert_eq!(state.total_shielded, 0);
        assert_eq!(state.authority, authority);
    }

    #[test]
    fn test_add_shielded() {
        let mut state = ShieldedPoolState::new([0u8; 32]);
        state.add_shielded(100).unwrap();
        assert_eq!(state.total_shielded, 100);
        state.add_shielded(50).unwrap();
        assert_eq!(state.total_shielded, 150);
    }

    #[test]
    fn test_remove_shielded() {
        let mut state = ShieldedPoolState::new([0u8; 32]);
        state.add_shielded(100).unwrap();
        state.remove_shielded(30).unwrap();
        assert_eq!(state.total_shielded, 70);
    }

    #[test]
    fn test_insufficient_balance() {
        let mut state = ShieldedPoolState::new([0u8; 32]);
        state.add_shielded(100).unwrap();
        let result = state.remove_shielded(150);
        assert!(result.is_err());
    }
}
