//! Universal Shielded Assets
//!
//! Any asset on YaCoin can be shielded - SOL, tokens, NFTs, or arbitrary data.
//! This module provides the unified asset representation used in shielded notes.

use borsh::{BorshDeserialize, BorshSerialize};
use blake2s_simd::Params as Blake2sParams;

/// Asset type discriminator
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum AssetType {
    /// Native SOL
    Native = 0,
    /// SPL Token (fungible)
    Token = 1,
    /// NFT (non-fungible token)
    NFT = 2,
    /// Arbitrary program data commitment
    ProgramData = 3,
}

/// Universal asset representation for shielded notes
///
/// Any asset on YaCoin can be represented and shielded using this structure.
/// The asset type and identifiers are hidden inside note commitments.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ShieldedAsset {
    /// Type of asset
    pub asset_type: AssetType,

    /// Asset identifier (mint address for tokens/NFTs, program_id for data)
    /// Zero for native SOL
    pub asset_id: [u8; 32],

    /// Secondary identifier (token_id for NFTs, data_hash for program data)
    /// Zero for fungible assets
    pub secondary_id: [u8; 32],

    /// Amount (always 1 for NFTs, 0 for pure data commitments)
    pub amount: u64,
}

impl ShieldedAsset {
    /// Create a native SOL asset
    pub fn native(amount: u64) -> Self {
        Self {
            asset_type: AssetType::Native,
            asset_id: [0u8; 32],
            secondary_id: [0u8; 32],
            amount,
        }
    }

    /// Create a fungible token asset
    pub fn token(mint: [u8; 32], amount: u64) -> Self {
        Self {
            asset_type: AssetType::Token,
            asset_id: mint,
            secondary_id: [0u8; 32],
            amount,
        }
    }

    /// Create an NFT asset
    pub fn nft(mint: [u8; 32], token_id: [u8; 32]) -> Self {
        Self {
            asset_type: AssetType::NFT,
            asset_id: mint,
            secondary_id: token_id,
            amount: 1, // NFTs always have amount = 1
        }
    }

    /// Create a program data commitment
    pub fn program_data(program_id: [u8; 32], data_hash: [u8; 32]) -> Self {
        Self {
            asset_type: AssetType::ProgramData,
            asset_id: program_id,
            secondary_id: data_hash,
            amount: 0,
        }
    }

    /// Check if this is a fungible asset (can be split/merged)
    pub fn is_fungible(&self) -> bool {
        matches!(self.asset_type, AssetType::Native | AssetType::Token)
    }

    /// Check if this is a non-fungible asset
    pub fn is_non_fungible(&self) -> bool {
        matches!(self.asset_type, AssetType::NFT)
    }

    /// Get the asset's unique type identifier for circuit constraints
    /// This binds the asset type + id into a single value for the circuit
    pub fn type_binding(&self) -> [u8; 32] {
        let mut hasher = Blake2sParams::new()
            .hash_length(32)
            .personal(b"YCoin_AB") // Asset Binding
            .to_state();

        hasher.update(&[self.asset_type as u8]);
        hasher.update(&self.asset_id);

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }

    /// Serialize to bytes for hashing
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(73);
        bytes.push(self.asset_type as u8);
        bytes.extend_from_slice(&self.asset_id);
        bytes.extend_from_slice(&self.secondary_id);
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes
    }
}

/// Universal shielded note that can hold any asset
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct UniversalNote {
    /// Diversifier for address derivation
    pub diversifier: [u8; 11],

    /// Diversified transmission key
    pub pk_d: [u8; 32],

    /// The shielded asset
    pub asset: ShieldedAsset,

    /// Note commitment randomness (as bytes, converted to Fr when needed)
    pub rcm: [u8; 32],
}

impl UniversalNote {
    /// Create a new universal note
    pub fn new(
        diversifier: [u8; 11],
        pk_d: [u8; 32],
        asset: ShieldedAsset,
        rcm: [u8; 32],
    ) -> Self {
        Self {
            diversifier,
            pk_d,
            asset,
            rcm,
        }
    }
}

/// Verify that a set of input and output assets balance correctly
///
/// For fungible assets: sum(inputs) == sum(outputs) for each asset type
/// For NFTs: each input NFT must appear exactly once in outputs (transfer) or not at all (burn)
pub fn verify_asset_balance(
    inputs: &[ShieldedAsset],
    outputs: &[ShieldedAsset],
    allow_burns: bool,
) -> bool {
    use std::collections::HashMap;

    // Track fungible balances per asset type binding
    let mut fungible_balances: HashMap<[u8; 32], i128> = HashMap::new();

    // Track NFT transfers
    let mut input_nfts: HashMap<([u8; 32], [u8; 32]), u32> = HashMap::new();
    let mut output_nfts: HashMap<([u8; 32], [u8; 32]), u32> = HashMap::new();

    // Process inputs
    for asset in inputs {
        if asset.is_fungible() {
            let binding = asset.type_binding();
            *fungible_balances.entry(binding).or_insert(0) += asset.amount as i128;
        } else if asset.is_non_fungible() {
            let key = (asset.asset_id, asset.secondary_id);
            *input_nfts.entry(key).or_insert(0) += 1;
        }
    }

    // Process outputs
    for asset in outputs {
        if asset.is_fungible() {
            let binding = asset.type_binding();
            *fungible_balances.entry(binding).or_insert(0) -= asset.amount as i128;
        } else if asset.is_non_fungible() {
            let key = (asset.asset_id, asset.secondary_id);
            *output_nfts.entry(key).or_insert(0) += 1;
        }
    }

    // Verify fungible balances are zero (conservation)
    for (_, balance) in &fungible_balances {
        if *balance != 0 {
            return false;
        }
    }

    // Verify NFT conservation
    for (nft_key, input_count) in &input_nfts {
        let output_count = output_nfts.get(nft_key).copied().unwrap_or(0);

        if output_count > *input_count {
            // Can't create NFTs from nothing
            return false;
        }

        if output_count < *input_count && !allow_burns {
            // NFT would be burned but burns not allowed
            return false;
        }
    }

    // Check no NFTs created from nothing
    for (nft_key, _) in &output_nfts {
        if !input_nfts.contains_key(nft_key) {
            // Output NFT doesn't exist in inputs
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_asset() {
        let asset = ShieldedAsset::native(1000);
        assert!(asset.is_fungible());
        assert!(!asset.is_non_fungible());
        assert_eq!(asset.amount, 1000);
    }

    #[test]
    fn test_token_asset() {
        let mint = [1u8; 32];
        let asset = ShieldedAsset::token(mint, 500);
        assert!(asset.is_fungible());
        assert_eq!(asset.asset_id, mint);
        assert_eq!(asset.amount, 500);
    }

    #[test]
    fn test_nft_asset() {
        let mint = [2u8; 32];
        let token_id = [3u8; 32];
        let asset = ShieldedAsset::nft(mint, token_id);
        assert!(asset.is_non_fungible());
        assert_eq!(asset.amount, 1);
        assert_eq!(asset.asset_id, mint);
        assert_eq!(asset.secondary_id, token_id);
    }

    #[test]
    fn test_fungible_balance() {
        let inputs = vec![
            ShieldedAsset::native(1000),
            ShieldedAsset::native(500),
        ];
        let outputs = vec![
            ShieldedAsset::native(1500),
        ];

        assert!(verify_asset_balance(&inputs, &outputs, false));
    }

    #[test]
    fn test_fungible_balance_mismatch() {
        let inputs = vec![
            ShieldedAsset::native(1000),
        ];
        let outputs = vec![
            ShieldedAsset::native(1500), // More than input!
        ];

        assert!(!verify_asset_balance(&inputs, &outputs, false));
    }

    #[test]
    fn test_nft_transfer() {
        let mint = [1u8; 32];
        let token_id = [2u8; 32];

        let inputs = vec![ShieldedAsset::nft(mint, token_id)];
        let outputs = vec![ShieldedAsset::nft(mint, token_id)];

        assert!(verify_asset_balance(&inputs, &outputs, false));
    }

    #[test]
    fn test_nft_cannot_duplicate() {
        let mint = [1u8; 32];
        let token_id = [2u8; 32];

        let inputs = vec![ShieldedAsset::nft(mint, token_id)];
        let outputs = vec![
            ShieldedAsset::nft(mint, token_id),
            ShieldedAsset::nft(mint, token_id), // Duplicate!
        ];

        assert!(!verify_asset_balance(&inputs, &outputs, false));
    }

    #[test]
    fn test_nft_burn_allowed() {
        let mint = [1u8; 32];
        let token_id = [2u8; 32];

        let inputs = vec![ShieldedAsset::nft(mint, token_id)];
        let outputs = vec![]; // Burn

        assert!(verify_asset_balance(&inputs, &outputs, true));
        assert!(!verify_asset_balance(&inputs, &outputs, false));
    }

    #[test]
    fn test_mixed_assets() {
        let token_mint = [1u8; 32];
        let nft_mint = [2u8; 32];
        let token_id = [3u8; 32];

        let inputs = vec![
            ShieldedAsset::native(1000),
            ShieldedAsset::token(token_mint, 500),
            ShieldedAsset::nft(nft_mint, token_id),
        ];
        let outputs = vec![
            ShieldedAsset::native(600),
            ShieldedAsset::native(400),
            ShieldedAsset::token(token_mint, 500),
            ShieldedAsset::nft(nft_mint, token_id),
        ];

        assert!(verify_asset_balance(&inputs, &outputs, false));
    }

    #[test]
    fn test_type_binding_different() {
        let native = ShieldedAsset::native(100);
        let token = ShieldedAsset::token([0u8; 32], 100);

        // Same asset_id (zeros) but different type = different binding
        assert_ne!(native.type_binding(), token.type_binding());
    }
}
