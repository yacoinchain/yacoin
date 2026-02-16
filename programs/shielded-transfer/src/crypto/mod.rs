//! Cryptographic primitives for shielded transactions
//!
//! This module provides:
//! - Pedersen commitments using the Jubjub curve
//! - Groth16 zk-SNARK proof verification
//! - Key derivation (spending keys, viewing keys)
//! - Note encryption/decryption
//! - GPU-accelerated proof generation
//! - Encrypted memos
//! - Stealth addresses
//! - Diversified payment addresses
//! - Viewing key export for compliance
//! - NFT/asset ownership proofs

pub mod pedersen;
pub mod groth16;
pub mod keys;
pub mod note;
pub mod gpu_prover;
pub mod universal_asset;
pub mod memo;
pub mod stealth;
pub mod viewing;
pub mod diversifier;
pub mod ownership;

// Core cryptographic primitives
pub use pedersen::{PedersenHash, NoteCommitment, ValueCommitment};
pub use groth16::{verify_spend_proof, verify_output_proof, Proof};
pub use keys::{SpendingKey, ViewingKey, FullViewingKey, IncomingViewingKey, OutgoingViewingKey};
pub use note::{Note, EncryptedNote};
pub use gpu_prover::{GpuProver, GpuProverConfig, GpuBackend, SpendWitness, OutputWitness};

// Universal assets
pub use universal_asset::{ShieldedAsset, AssetType, UniversalNote, verify_asset_balance};

// Privacy features
pub use memo::{EncryptedMemo, MemoType, MAX_MEMO_SIZE};
pub use stealth::{StealthMetaAddress, StealthKeys, StealthAddress, StealthSpendKey};
pub use viewing::{FullViewingKeyData, IncomingViewingKeyData, OutgoingViewingKeyData, PaymentDisclosure, ViewingKeyExport, ViewingKeyType};
pub use diversifier::{Diversifier, DiversifiedAddress, AddressGenerator};
pub use ownership::{CollectionOwnershipProof, TokenGatedProof, OwnershipClaim, OwnershipOpening};
