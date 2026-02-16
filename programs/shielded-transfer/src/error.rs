//! Error types for the shielded transfer program

use thiserror::Error;

/// Errors that can occur in the shielded transfer program
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ShieldedTransferError {
    #[error("Invalid proof")]
    InvalidProof,

    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    #[error("Nullifier already spent (double-spend attempt)")]
    NullifierAlreadySpent,

    #[error("Invalid anchor (merkle root not found)")]
    InvalidAnchor,

    #[error("Value balance mismatch")]
    ValueBalanceMismatch,

    #[error("Invalid binding signature")]
    InvalidBindingSignature,

    #[error("Invalid spend authorization signature")]
    InvalidSpendAuthSig,

    #[error("Commitment tree full")]
    CommitmentTreeFull,

    #[error("Nullifier set full")]
    NullifierSetFull,

    #[error("Invalid note encryption")]
    InvalidNoteEncryption,

    #[error("Insufficient shielded balance")]
    InsufficientShieldedBalance,

    #[error("Invalid instruction data")]
    InvalidInstructionData,

    #[error("Account not initialized")]
    AccountNotInitialized,

    #[error("Account already initialized")]
    AccountAlreadyInitialized,

    #[error("Invalid account owner")]
    InvalidAccountOwner,

    #[error("Arithmetic overflow")]
    ArithmeticOverflow,

    #[error("Invalid account data")]
    InvalidAccountData,

    #[error("Serialization error")]
    SerializationError,

    #[error("Account too small")]
    AccountTooSmall,
}

impl From<ShieldedTransferError> for solana_instruction_error::InstructionError {
    fn from(e: ShieldedTransferError) -> Self {
        match e {
            ShieldedTransferError::InvalidProof => Self::InvalidInstructionData,
            ShieldedTransferError::ProofVerificationFailed(_) => Self::InvalidInstructionData,
            ShieldedTransferError::NullifierAlreadySpent => Self::InvalidArgument,
            ShieldedTransferError::InvalidAnchor => Self::InvalidArgument,
            ShieldedTransferError::ValueBalanceMismatch => Self::InvalidArgument,
            ShieldedTransferError::InvalidBindingSignature => Self::InvalidInstructionData,
            ShieldedTransferError::InvalidSpendAuthSig => Self::InvalidInstructionData,
            ShieldedTransferError::CommitmentTreeFull => Self::AccountDataTooSmall,
            ShieldedTransferError::NullifierSetFull => Self::AccountDataTooSmall,
            ShieldedTransferError::InvalidNoteEncryption => Self::InvalidInstructionData,
            ShieldedTransferError::InsufficientShieldedBalance => Self::InsufficientFunds,
            ShieldedTransferError::InvalidInstructionData => Self::InvalidInstructionData,
            ShieldedTransferError::AccountNotInitialized => Self::UninitializedAccount,
            ShieldedTransferError::AccountAlreadyInitialized => Self::AccountAlreadyInitialized,
            ShieldedTransferError::InvalidAccountOwner => Self::InvalidAccountOwner,
            ShieldedTransferError::ArithmeticOverflow => Self::ArithmeticOverflow,
            ShieldedTransferError::InvalidAccountData => Self::InvalidAccountData,
            ShieldedTransferError::SerializationError => Self::InvalidInstructionData,
            ShieldedTransferError::AccountTooSmall => Self::AccountDataTooSmall,
        }
    }
}
