//! Shielded transfer instructions
//!
//! Defines the instruction types for the shielded transfer program.
//! Supports shielding ANY asset: SOL, SPL tokens, NFTs, or arbitrary data.

use borsh::{BorshDeserialize, BorshSerialize};
use crate::{SpendDescription, OutputDescription};
use crate::crypto::universal_asset::ShieldedAsset;

/// Shielded transfer instructions
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum ShieldedInstruction {
    /// Shield transparent tokens into the shielded pool
    ///
    /// Accounts:
    /// 0. `[signer]` Sender (transparent account)
    /// 1. `[writable]` Shielded pool account
    /// 2. `[writable]` Commitment tree account
    Shield {
        /// Amount to shield (in atomic units)
        amount: u64,
        /// Output description with proof
        output: OutputDescription,
    },

    /// Unshield tokens from shielded pool to transparent account
    ///
    /// Accounts:
    /// 0. `[writable]` Recipient (transparent account)
    /// 1. `[writable]` Shielded pool account
    /// 2. `[writable]` Nullifier set account
    /// 3. `[]` Commitment tree account
    Unshield {
        /// Amount to unshield (in atomic units)
        amount: u64,
        /// Spend description with proof
        spend: SpendDescription,
        /// Recipient pubkey
        recipient: [u8; 32],
    },

    /// Fully shielded transfer (shield to shield)
    ///
    /// Accounts:
    /// 0. `[writable]` Shielded pool account
    /// 1. `[writable]` Commitment tree account
    /// 2. `[writable]` Nullifier set account
    ShieldedTransfer {
        /// Spend descriptions (inputs)
        spends: Vec<SpendDescription>,
        /// Output descriptions (outputs)
        outputs: Vec<OutputDescription>,
        /// Binding signature proving value balance
        binding_sig: [u8; 64],
    },

    /// Initialize the shielded pool and state accounts
    ///
    /// Accounts:
    /// 0. `[signer]` Authority
    /// 1. `[writable]` Shielded pool account (to create)
    /// 2. `[writable]` Commitment tree account (to create)
    /// 3. `[writable]` Nullifier set account (to create)
    InitializePool {
        /// Initial authority (can be zero for permissionless)
        authority: [u8; 32],
    },

    // =========================================================================
    // Universal Asset Instructions (shield ANY asset type)
    // =========================================================================

    /// Shield any SPL token into the shielded pool
    ///
    /// Accounts:
    /// 0. `[signer]` Token owner
    /// 1. `[writable]` Source token account
    /// 2. `[writable]` Pool token account (escrow)
    /// 3. `[writable]` Commitment tree account
    /// 4. `[writable]` Recent anchors account
    /// 5. `[]` Token program
    ShieldToken {
        /// Token mint address
        mint: [u8; 32],
        /// Amount to shield
        amount: u64,
        /// Output description with proof
        output: OutputDescription,
    },

    /// Unshield SPL tokens from the shielded pool
    ///
    /// Accounts:
    /// 0. `[writable]` Pool token account (escrow)
    /// 1. `[writable]` Destination token account
    /// 2. `[writable]` Commitment tree account
    /// 3. `[writable]` Nullifier set account
    /// 4. `[writable]` Recent anchors account
    /// 5. `[]` Token program
    /// 6. `[]` Pool authority PDA
    UnshieldToken {
        /// Token mint address
        mint: [u8; 32],
        /// Amount to unshield
        amount: u64,
        /// Spend description with proof
        spend: SpendDescription,
        /// Recipient token account
        recipient: [u8; 32],
    },

    /// Shield an NFT into the shielded pool
    ///
    /// Accounts:
    /// 0. `[signer]` NFT owner
    /// 1. `[writable]` Source NFT token account
    /// 2. `[writable]` Pool NFT escrow account
    /// 3. `[writable]` Commitment tree account
    /// 4. `[writable]` Recent anchors account
    /// 5. `[]` Token program
    ShieldNFT {
        /// NFT mint address
        mint: [u8; 32],
        /// Unique token identifier (for editions/collections)
        token_id: [u8; 32],
        /// Output description with proof
        output: OutputDescription,
    },

    /// Unshield an NFT from the shielded pool
    ///
    /// Accounts:
    /// 0. `[writable]` Pool NFT escrow account
    /// 1. `[writable]` Destination NFT token account
    /// 2. `[writable]` Commitment tree account
    /// 3. `[writable]` Nullifier set account
    /// 4. `[writable]` Recent anchors account
    /// 5. `[]` Token program
    /// 6. `[]` Pool authority PDA
    UnshieldNFT {
        /// NFT mint address
        mint: [u8; 32],
        /// Unique token identifier
        token_id: [u8; 32],
        /// Spend description with proof
        spend: SpendDescription,
        /// Recipient token account
        recipient: [u8; 32],
    },

    /// Universal shielded transfer supporting mixed asset types
    ///
    /// Can transfer any combination of:
    /// - Native SOL
    /// - SPL tokens (multiple different mints)
    /// - NFTs
    ///
    /// The zk proof verifies that for each asset type:
    /// - Fungible: sum(inputs) == sum(outputs)
    /// - NFTs: each input NFT appears exactly once in outputs
    ///
    /// Accounts:
    /// 0. `[writable]` Shielded pool account
    /// 1. `[writable]` Commitment tree account
    /// 2. `[writable]` Nullifier set account
    /// 3. `[writable]` Recent anchors account
    UniversalShieldedTransfer {
        /// Input assets being spent
        spend_assets: Vec<ShieldedAsset>,
        /// Spend descriptions with proofs (one per input)
        spends: Vec<SpendDescription>,
        /// Output assets being created
        output_assets: Vec<ShieldedAsset>,
        /// Output descriptions with proofs (one per output)
        outputs: Vec<OutputDescription>,
        /// Binding signature proving asset conservation
        binding_sig: [u8; 64],
    },
}

impl ShieldedInstruction {
    /// Get the instruction discriminant
    pub fn discriminant(&self) -> u8 {
        match self {
            ShieldedInstruction::Shield { .. } => 0,
            ShieldedInstruction::Unshield { .. } => 1,
            ShieldedInstruction::ShieldedTransfer { .. } => 2,
            ShieldedInstruction::InitializePool { .. } => 3,
            ShieldedInstruction::ShieldToken { .. } => 4,
            ShieldedInstruction::UnshieldToken { .. } => 5,
            ShieldedInstruction::ShieldNFT { .. } => 6,
            ShieldedInstruction::UnshieldNFT { .. } => 7,
            ShieldedInstruction::UniversalShieldedTransfer { .. } => 8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GROTH_PROOF_SIZE, ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE};

    fn create_test_output() -> OutputDescription {
        OutputDescription {
            cv: [1u8; 32],
            cmu: [2u8; 32],
            ephemeral_key: [3u8; 32],
            enc_ciphertext: [0u8; ENC_CIPHERTEXT_SIZE],
            out_ciphertext: [0u8; OUT_CIPHERTEXT_SIZE],
            zkproof: [0u8; GROTH_PROOF_SIZE],
        }
    }

    fn create_test_spend() -> SpendDescription {
        SpendDescription {
            cv: [1u8; 32],
            anchor: [2u8; 32],
            nullifier: [3u8; 32],
            rk: [4u8; 32],
            zkproof: [0u8; GROTH_PROOF_SIZE],
            spend_auth_sig: [0u8; 64],
        }
    }

    #[test]
    fn test_shield_serialization() {
        let instruction = ShieldedInstruction::Shield {
            amount: 1000,
            output: create_test_output(),
        };

        let serialized = borsh::to_vec(&instruction).unwrap();
        let deserialized: ShieldedInstruction = borsh::from_slice(&serialized).unwrap();

        match deserialized {
            ShieldedInstruction::Shield { amount, .. } => {
                assert_eq!(amount, 1000);
            }
            _ => panic!("Wrong instruction type"),
        }
    }

    #[test]
    fn test_unshield_serialization() {
        let instruction = ShieldedInstruction::Unshield {
            amount: 500,
            spend: create_test_spend(),
            recipient: [42u8; 32],
        };

        let serialized = borsh::to_vec(&instruction).unwrap();
        let deserialized: ShieldedInstruction = borsh::from_slice(&serialized).unwrap();

        match deserialized {
            ShieldedInstruction::Unshield { amount, recipient, .. } => {
                assert_eq!(amount, 500);
                assert_eq!(recipient[0], 42);
            }
            _ => panic!("Wrong instruction type"),
        }
    }

    #[test]
    fn test_shielded_transfer_serialization() {
        let instruction = ShieldedInstruction::ShieldedTransfer {
            spends: vec![create_test_spend()],
            outputs: vec![create_test_output()],
            binding_sig: [5u8; 64],
        };

        let serialized = borsh::to_vec(&instruction).unwrap();
        let deserialized: ShieldedInstruction = borsh::from_slice(&serialized).unwrap();

        match deserialized {
            ShieldedInstruction::ShieldedTransfer { spends, outputs, .. } => {
                assert_eq!(spends.len(), 1);
                assert_eq!(outputs.len(), 1);
            }
            _ => panic!("Wrong instruction type"),
        }
    }

    #[test]
    fn test_discriminants() {
        assert_eq!(ShieldedInstruction::Shield { amount: 0, output: create_test_output() }.discriminant(), 0);
        assert_eq!(ShieldedInstruction::Unshield { amount: 0, spend: create_test_spend(), recipient: [0u8; 32] }.discriminant(), 1);
        assert_eq!(ShieldedInstruction::ShieldedTransfer { spends: vec![], outputs: vec![], binding_sig: [0u8; 64] }.discriminant(), 2);
        assert_eq!(ShieldedInstruction::InitializePool { authority: [0u8; 32] }.discriminant(), 3);
    }

    #[test]
    fn test_shield_serialized_size() {
        // This test verifies the expected size of a Shield instruction
        // to help debug serialization mismatches
        let instruction = ShieldedInstruction::Shield {
            amount: 1000,
            output: create_test_output(),
        };

        let serialized = borsh::to_vec(&instruction).unwrap();

        // Expected size:
        // - 1 byte: enum discriminant (u8)
        // - 8 bytes: amount (u64)
        // - OutputDescription:
        //   - 32 bytes: cv
        //   - 32 bytes: cmu
        //   - 32 bytes: ephemeral_key
        //   - 68 bytes: enc_ciphertext (ENC_CIPHERTEXT_SIZE)
        //   - 80 bytes: out_ciphertext (OUT_CIPHERTEXT_SIZE)
        //   - 192 bytes: zkproof (GROTH_PROOF_SIZE)
        // Total: 1 + 8 + 32 + 32 + 32 + 68 + 80 + 192 = 445 bytes
        let expected_size = 1 + 8 + 32 + 32 + 32 + ENC_CIPHERTEXT_SIZE + OUT_CIPHERTEXT_SIZE + GROTH_PROOF_SIZE;
        assert_eq!(expected_size, 445);
        assert_eq!(serialized.len(), expected_size, "Shield instruction size mismatch");

        // First byte should be discriminant 0
        assert_eq!(serialized[0], 0, "Wrong discriminant");

        // Bytes 1-8 should be amount (1000 in little-endian)
        let amount_bytes = &serialized[1..9];
        assert_eq!(amount_bytes, &1000u64.to_le_bytes(), "Wrong amount encoding");

        println!("Shield instruction serialized size: {} bytes", serialized.len());
        println!("First 16 bytes: {:?}", &serialized[..16]);
    }

    #[test]
    fn test_cross_crate_serialization() {
        // This test simulates the exact serialization flow from CLI to native program
        // to ensure there's no mismatch

        // Create instruction exactly as CLI does
        let instruction_data = ShieldedInstruction::Shield {
            amount: 100_000_000, // 0.1 YAC
            output: create_test_output(),
        };

        // Serialize with borsh::to_vec (same as CLI)
        let serialized = borsh::to_vec(&instruction_data).expect("serialize failed");

        println!("Cross-crate test:");
        println!("  Serialized length: {}", serialized.len());
        println!("  First 16 bytes: {:02x?}", &serialized[..16.min(serialized.len())]);

        // Deserialize with try_from_slice (same as native program)
        let deserialized = ShieldedInstruction::try_from_slice(&serialized)
            .expect("deserialize failed - this is what native.rs does");

        // Verify
        match deserialized {
            ShieldedInstruction::Shield { amount, output } => {
                assert_eq!(amount, 100_000_000);
                assert_eq!(output.cv, [1u8; 32]);
                println!("  Deserialization successful!");
            }
            _ => panic!("Wrong instruction type after deserialization"),
        }
    }

    #[test]
    fn test_init_pool_serialization() {
        // Also test InitializePool since that works
        let instruction_data = ShieldedInstruction::InitializePool {
            authority: [42u8; 32],
        };

        let serialized = borsh::to_vec(&instruction_data).expect("serialize failed");

        println!("InitializePool test:");
        println!("  Serialized length: {}", serialized.len());
        println!("  First 16 bytes: {:02x?}", &serialized[..16.min(serialized.len())]);

        // Expected: discriminant (3) + authority (32 bytes) = 33 bytes
        assert_eq!(serialized.len(), 33);
        assert_eq!(serialized[0], 3); // InitializePool discriminant

        let deserialized = ShieldedInstruction::try_from_slice(&serialized)
            .expect("deserialize failed");

        match deserialized {
            ShieldedInstruction::InitializePool { authority } => {
                assert_eq!(authority, [42u8; 32]);
                println!("  Deserialization successful!");
            }
            _ => panic!("Wrong instruction type after deserialization"),
        }
    }
}
