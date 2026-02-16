//! YaCoin Shielded Transfer Program
//!
//! This program enables fully private transactions using zk-SNARKs.
//! Based on Sapling protocol (zk-SNARK privacy layer) integrated with YaCoin's high-throughput runtime.
//!
//! # Overview
//!
//! Shielded transactions hide:
//! - Sender address
//! - Recipient address
//! - Transaction amount
//!
//! This is achieved using:
//! - Note commitments: Hash of (value, recipient, randomness)
//! - Nullifiers: Unique identifier to prevent double-spending
//! - zk-SNARK proofs: Proves transaction validity without revealing details

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod accounts;
pub mod commitment_tree;
pub mod nullifier_set;
pub mod processor;
pub mod state;
pub mod instruction;
pub mod error;
pub mod genesis;
pub mod rpc;

#[cfg(feature = "sapling")]
pub mod crypto;

#[cfg(feature = "native")]
pub mod native;

#[cfg(feature = "native")]
pub use native::Entrypoint;

pub use commitment_tree::{IncrementalMerkleTree, MerkleWitness, RecentAnchors};
pub use nullifier_set::NullifierSet;
pub use instruction::ShieldedInstruction;
pub use error::ShieldedTransferError;

/// Size of a Groth16 proof in bytes
pub const GROTH_PROOF_SIZE: usize = 192;

/// Size of a note commitment
pub const NOTE_COMMITMENT_SIZE: usize = 32;

/// Size of a nullifier
pub const NULLIFIER_SIZE: usize = 32;

/// Size of encrypted note ciphertext
pub const ENC_CIPHERTEXT_SIZE: usize = 580;

/// Size of outgoing ciphertext
pub const OUT_CIPHERTEXT_SIZE: usize = 80;

/// Compute units for verifying a shielded spend (with native syscall: ~75k instead of 500k)
pub const VERIFY_SPEND_COMPUTE_UNITS: u64 = 75_000;

/// Compute units for verifying a shielded output (with native syscall: ~75k instead of 450k)
pub const VERIFY_OUTPUT_COMPUTE_UNITS: u64 = 75_000;

/// Maximum size of a shielded transaction in bytes
/// Shielded transactions require more space due to zk-proofs and encrypted data:
/// - SpendDescription: 384 bytes each (cv + anchor + nullifier + rk + zkproof + spend_auth_sig)
/// - OutputDescription: 948 bytes each (cv + cmu + epk + enc_ciphertext + out_ciphertext + zkproof)
/// 4KB allows for transactions with up to 2 spends and 2 outputs with room for headers
pub const SHIELDED_PACKET_DATA_SIZE: usize = 4096;

/// Maximum number of spend descriptions in a single transaction
pub const MAX_SPENDS_PER_TX: usize = 4;

/// Maximum number of output descriptions in a single transaction
pub const MAX_OUTPUTS_PER_TX: usize = 4;

/// Size of a SpendDescription
pub const SPEND_DESCRIPTION_SIZE: usize = 32 + 32 + NULLIFIER_SIZE + 32 + GROTH_PROOF_SIZE + 64; // 384 bytes

/// Size of an OutputDescription
pub const OUTPUT_DESCRIPTION_SIZE: usize = 32 + NOTE_COMMITMENT_SIZE + 32 + ENC_CIPHERTEXT_SIZE + OUT_CIPHERTEXT_SIZE + GROTH_PROOF_SIZE; // 948 bytes

/// Program ID for shielded transfers
pub mod id {
    use solana_pubkey::Pubkey;

    /// The program ID for YaCoin shielded transfers
    pub const ID: Pubkey = Pubkey::new_from_array([
        0x53, 0x68, 0x69, 0x65, 0x4c, 0x64, 0x65, 0x64, // "ShieLded"
        0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, // "Transfer"
        0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, // "11111111"
        0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, // "11111111"
    ]);

    pub fn id() -> Pubkey {
        ID
    }

    pub fn check_id(id: &Pubkey) -> bool {
        *id == ID
    }
}

/// Description of a shielded spend (consuming a note)
#[derive(Clone, Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SpendDescription {
    /// Value commitment (Pedersen commitment to value)
    pub cv: [u8; 32],
    /// Merkle root anchor
    pub anchor: [u8; 32],
    /// Nullifier (prevents double-spending)
    pub nullifier: [u8; NULLIFIER_SIZE],
    /// Randomized verification key
    pub rk: [u8; 32],
    /// zk-SNARK proof
    pub zkproof: [u8; GROTH_PROOF_SIZE],
    /// Spend authorization signature
    pub spend_auth_sig: [u8; 64],
}

/// Description of a shielded output (creating a note)
#[derive(Clone, Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct OutputDescription {
    /// Value commitment (Pedersen commitment to value)
    pub cv: [u8; 32],
    /// Note commitment
    pub cmu: [u8; NOTE_COMMITMENT_SIZE],
    /// Ephemeral public key for note encryption
    pub ephemeral_key: [u8; 32],
    /// Encrypted note
    pub enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    /// Encrypted outgoing viewing key data
    pub out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
    /// zk-SNARK proof
    pub zkproof: [u8; GROTH_PROOF_SIZE],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_id() {
        assert!(id::check_id(&id::id()));
    }

    #[test]
    fn test_sizes() {
        assert_eq!(GROTH_PROOF_SIZE, 192);
        assert_eq!(NOTE_COMMITMENT_SIZE, 32);
        assert_eq!(NULLIFIER_SIZE, 32);
        assert_eq!(SPEND_DESCRIPTION_SIZE, 384);
        assert_eq!(OUTPUT_DESCRIPTION_SIZE, 948);
        // A 2-in-2-out shielded tx needs ~2896 bytes, well under 4KB
        assert!(2 * SPEND_DESCRIPTION_SIZE + 2 * OUTPUT_DESCRIPTION_SIZE + 200 < SHIELDED_PACKET_DATA_SIZE);
    }

    #[test]
    fn test_compute_units() {
        // With native syscall, verification is much faster
        assert!(VERIFY_SPEND_COMPUTE_UNITS <= 100_000);
        assert!(VERIFY_OUTPUT_COMPUTE_UNITS <= 100_000);
    }
}
