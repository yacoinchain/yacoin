//! YaCoin Shielded Wallet SDK
//!
//! This library provides functionality for creating and managing shielded transactions
//! on the YaCoin blockchain.
//!
//! # Example
//!
//! ```ignore
//! use yacoin_shielded_wallet::{ShieldedWallet, ShieldedAddress};
//!
//! // Create a new wallet from seed
//! let seed = [0u8; 32];
//! let mut wallet = ShieldedWallet::from_seed(&seed);
//!
//! // Get a payment address
//! let address = wallet.default_address()?;
//!
//! // Create a shielded transfer
//! let instruction = wallet.create_shield_instruction(1000, from_account, pool_account)?;
//! ```

pub mod error;
pub mod keys;
pub mod prover;
pub mod transaction;
pub mod wallet;

// Re-export main types
pub use error::{WalletError, WalletResult};
pub use keys::{ExtendedSpendingKey, ShieldedAddress, ViewingKey};
pub use transaction::{
    ShieldBuilder, ShieldedTransferBuilder, UnshieldBuilder, WalletNote,
    ShieldedTransaction, ShieldedTxType,
};
pub use wallet::{ShieldedWallet, ViewingKeyExport, WalletBackup, WatchOnlyWallet};

/// Re-export crypto types from shielded-transfer
pub use yacoin_shielded_transfer::crypto;

/// Re-export core instruction types
pub use yacoin_shielded_transfer::{OutputDescription, SpendDescription};
