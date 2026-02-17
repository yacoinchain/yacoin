//! Error types for the shielded wallet

use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Invalid spending key")]
    InvalidSpendingKey,

    #[error("Invalid viewing key")]
    InvalidViewingKey,

    #[error("Invalid diversifier - cannot map to curve point")]
    InvalidDiversifier,

    #[error("Invalid payment address")]
    InvalidPaymentAddress,

    #[error("Invalid note")]
    InvalidNote,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Sapling parameters not found. Download with: yacoin-params fetch")]
    ParamsNotFound,

    #[error("Invalid Merkle witness")]
    InvalidWitness,

    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}
