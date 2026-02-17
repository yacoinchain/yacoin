//! YaCoin Shielded Wallet SDK
//!
//! This SDK provides everything needed for shielded transactions:
//! - Key generation and derivation (Sapling-compatible)
//! - Note creation and encryption
//! - Commitment computation
//! - Proof generation using our own Sapling circuit
//!
//! All crypto primitives are implemented in-house, not using external zcash crates.

pub mod keys;
pub mod note;
pub mod commitment;
pub mod prover;
pub mod wallet;
pub mod error;

// Re-exports for convenience
pub use keys::{SpendingKey, FullViewingKey, IncomingViewingKey, OutgoingViewingKey, PaymentAddress, Diversifier};
pub use note::{Note, EncryptedNote};
pub use commitment::{NoteCommitment, ValueCommitment};
pub use prover::{SpendProof, OutputProof, ShieldedProver};
pub use wallet::{ShieldedWallet, ShieldedBalance};
pub use error::WalletError;

/// Groth16 proof size (192 bytes)
pub const GROTH_PROOF_SIZE: usize = 192;

/// Encrypted note ciphertext size
pub const ENC_CIPHERTEXT_SIZE: usize = 580;

/// Outgoing ciphertext size
pub const OUT_CIPHERTEXT_SIZE: usize = 80;
