//! Wallet error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Invalid spending key")]
    InvalidSpendingKey,

    #[error("Invalid viewing key")]
    InvalidViewingKey,

    #[error("Invalid address")]
    InvalidAddress,

    #[error("Invalid key")]
    InvalidKey,

    #[error("Invalid merkle root")]
    InvalidMerkleRoot,

    #[error("Insufficient shielded balance")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("Insufficient funds")]
    InsufficientFunds,

    #[error("No notes available to spend")]
    NoNotesAvailable,

    #[error("Note not spendable")]
    NoteNotSpendable,

    #[error("Invalid note")]
    InvalidNote,

    #[error("Value balance mismatch")]
    ValueBalanceMismatch,

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Transaction building failed: {0}")]
    TransactionBuildFailed(String),

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Decryption error")]
    DecryptionError,

    #[error("Encryption error")]
    EncryptionError,

    #[error("Serialization error")]
    SerializationError,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Parameters not loaded")]
    ParamsNotLoaded,

    #[error("Invalid backup")]
    InvalidBackup,
}

pub type WalletResult<T> = Result<T, WalletError>;
