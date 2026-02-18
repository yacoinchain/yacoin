//! Native runtime entrypoint for the YaCoin Shielded Transfer program
//!
//! This module provides the native entrypoint for running the shielded transfer
//! program as a builtin in the YaCoin runtime.
//!
//! State is stored in PDAs (Program Derived Addresses):
//! - Pool state: tracks total shielded value
//! - Commitment tree: Merkle tree of note commitments
//! - Nullifier set: prevents double-spending
//! - Recent anchors: allows spending against recent roots

#![cfg(feature = "native")]

use solana_program_runtime::declare_process_instruction;
use solana_program_runtime::solana_sbpf::vm::ContextObject;
use solana_instruction_error::InstructionError;
use solana_svm_log_collector::ic_msg;
use borsh::BorshDeserialize;

use crate::{
    accounts::{
        NullifierSetAccount, RecentAnchorsAccount,
        load_pool_state, save_pool_state,
        load_commitment_tree, save_commitment_tree,
        load_nullifier_set, save_nullifier_set,
        load_recent_anchors, save_recent_anchors,
        MAX_RECENT_ANCHORS,
    },
    commitment_tree::IncrementalMerkleTree,
    instruction::ShieldedInstruction,
    processor::{
        process_shield, process_unshield, process_shielded_transfer,
        calculate_compute_units,
    },
    state::ShieldedPoolState,
};

/// Default compute units for shielded transfer operations
/// This is high because zk-SNARK verification is computationally intensive
pub const DEFAULT_COMPUTE_UNITS: u64 = 1_000_000;

declare_process_instruction!(Entrypoint, DEFAULT_COMPUTE_UNITS, |invoke_context| {
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;

    let data = instruction_context.get_instruction_data();
    if data.is_empty() {
        ic_msg!(invoke_context, "Shielded: empty instruction data");
        return Err(InstructionError::InvalidInstructionData);
    }

    // Debug: log instruction data info
    ic_msg!(invoke_context, "Shielded: data len={}, discriminant={}", data.len(), data[0]);

    let instruction = match ShieldedInstruction::try_from_slice(data) {
        Ok(ix) => ix,
        Err(e) => {
            ic_msg!(invoke_context, "Shielded: borsh error: {:?}", e);
            // Log first 32 bytes as hex for debugging
            let hex_dump: String = data[..data.len().min(32)].iter()
                .map(|b| format!("{:02x}", b))
                .collect();
            ic_msg!(invoke_context, "Shielded: first 32 bytes hex: {}", hex_dump);
            return Err(InstructionError::InvalidInstructionData);
        }
    };

    let num_accounts = instruction_context.get_number_of_instruction_accounts();
    ic_msg!(invoke_context, "Shielded: instruction parsed, accounts={}", num_accounts);

    match instruction {
        ShieldedInstruction::Shield { amount, output } => {
            ic_msg!(invoke_context, "Shield: amount={}", amount);
            // Accounts: 0=Funder, 1=Pool, 2=Tree, 3=System Program
            if num_accounts < 3 {
                return Err(InstructionError::MissingAccount);
            }

            // Verify funder is a signer
            {
                let funder = instruction_context
                    .try_borrow_instruction_account(0)?;
                if !funder.is_signer() {
                    return Err(InstructionError::MissingRequiredSignature);
                }
            }

            // Note: Lamport transfer from funder to pool is done via System Program
            // in a separate instruction before this one. The CLI handles this.

            // Load state
            let pool_data = instruction_context
                .try_borrow_instruction_account(1)?;
            let mut pool_state = load_pool_state(pool_data.get_data())
                .map_err(|_| InstructionError::InvalidAccountData)?;
            drop(pool_data);

            let tree_data = instruction_context
                .try_borrow_instruction_account(2)?;
            let mut commitment_tree = load_commitment_tree(tree_data.get_data())
                .map_err(|_| InstructionError::InvalidAccountData)?;
            drop(tree_data);

            // Process shield
            process_shield(amount, &output, &mut pool_state, &mut commitment_tree)
                .map_err(|e| InstructionError::from(e))?;

            // Save state
            {
                let mut pool_data = instruction_context
                    .try_borrow_instruction_account(1)?;
                save_pool_state(&pool_state, pool_data.get_data_mut()?)
                    .map_err(|_| InstructionError::InvalidAccountData)?;
            }
            {
                let mut tree_data = instruction_context
                    .try_borrow_instruction_account(2)?;
                save_commitment_tree(&commitment_tree, tree_data.get_data_mut()?)
                    .map_err(|_| InstructionError::InvalidAccountData)?;
            }

            // Update anchors
            {
                let anchor_data = instruction_context
                    .try_borrow_instruction_account(3)?;
                let mut anchors = load_recent_anchors(anchor_data.get_data())
                    .unwrap_or_else(|_| RecentAnchorsAccount {
                        anchors: Vec::new(),
                        position: 0,
                        max_size: MAX_RECENT_ANCHORS as u64,
                    });
                drop(anchor_data);

                anchors.add(commitment_tree.root());

                let mut anchor_data = instruction_context
                    .try_borrow_instruction_account(3)?;
                save_recent_anchors(&anchors, anchor_data.get_data_mut()?)
                    .map_err(|_| InstructionError::InvalidAccountData)?;
            }

            Ok(())
        }

        ShieldedInstruction::Unshield { amount, spend, recipient } => {
            // Accounts: 0=Pool, 1=Tree, 2=Nullifiers, 3=Anchors, 4=Recipient
            if num_accounts < 5 {
                return Err(InstructionError::MissingAccount);
            }

            // Verify recipient account matches instruction data
            {
                let recipient_account = instruction_context
                    .try_borrow_instruction_account(4)?;
                if recipient_account.get_key().as_ref() != &recipient {
                    return Err(InstructionError::InvalidArgument);
                }
            }

            // Load state
            let pool_data = instruction_context
                .try_borrow_instruction_account(0)?;
            let mut pool_state = load_pool_state(pool_data.get_data())
                .map_err(|_| InstructionError::InvalidAccountData)?;
            drop(pool_data);

            let tree_data = instruction_context
                .try_borrow_instruction_account(1)?;
            let commitment_tree = load_commitment_tree(tree_data.get_data())
                .map_err(|_| InstructionError::InvalidAccountData)?;
            drop(tree_data);

            let nf_data = instruction_context
                .try_borrow_instruction_account(2)?;
            let mut nullifier_account = load_nullifier_set(nf_data.get_data())
                .unwrap_or_else(|_| NullifierSetAccount {
                    count: 0,
                    nullifiers: Vec::new(),
                    bloom_filter: None,
                });
            drop(nf_data);

            let anchor_data = instruction_context
                .try_borrow_instruction_account(3)?;
            let anchors = load_recent_anchors(anchor_data.get_data())
                .unwrap_or_else(|_| RecentAnchorsAccount {
                    anchors: vec![commitment_tree.root()],
                    position: 1,
                    max_size: MAX_RECENT_ANCHORS as u64,
                });
            drop(anchor_data);

            // Validate anchor
            if !anchors.contains(&spend.anchor) && spend.anchor != commitment_tree.root() {
                return Err(InstructionError::Custom(2));
            }

            // Check double-spend
            if nullifier_account.contains(&spend.nullifier) {
                return Err(InstructionError::Custom(1));
            }

            let mut nullifier_set = nullifier_account.to_set();
            let recent = anchors.to_anchors();

            process_unshield(
                amount,
                &spend,
                &mut pool_state,
                &mut nullifier_set,
                &commitment_tree,
                Some(&recent),
            ).map_err(|e| InstructionError::from(e))?;

            nullifier_account.insert(spend.nullifier)
                .map_err(|_| InstructionError::Custom(1))?;

            // Save state
            {
                let mut pool_data = instruction_context
                    .try_borrow_instruction_account(0)?;
                save_pool_state(&pool_state, pool_data.get_data_mut()?)
                    .map_err(|_| InstructionError::InvalidAccountData)?;
            }
            {
                let mut nf_data = instruction_context
                    .try_borrow_instruction_account(2)?;
                save_nullifier_set(&nullifier_account, nf_data.get_data_mut()?)
                    .map_err(|_| InstructionError::InvalidAccountData)?;
            }

            // Transfer lamports from pool to recipient
            {
                let mut pool = instruction_context
                    .try_borrow_instruction_account(0)?;

                // Debit pool
                pool.checked_sub_lamports(amount)?;
            }
            {
                let mut recipient_account = instruction_context
                    .try_borrow_instruction_account(4)?;

                // Credit recipient
                recipient_account.checked_add_lamports(amount)?;
            }

            Ok(())
        }

        ShieldedInstruction::ShieldedTransfer { spends, outputs, binding_sig } => {
            // Accounts: 0=Pool, 1=Tree, 2=Nullifiers, 3=Anchors
            if num_accounts < 4 {
                return Err(InstructionError::MissingAccount);
            }

            let required_compute = calculate_compute_units(spends.len(), outputs.len());
            if required_compute > invoke_context.get_remaining() {
                return Err(InstructionError::ComputationalBudgetExceeded);
            }

            // Load state
            let pool_data = instruction_context
                .try_borrow_instruction_account(0)?;
            let mut pool_state = load_pool_state(pool_data.get_data())
                .map_err(|_| InstructionError::InvalidAccountData)?;
            drop(pool_data);

            let tree_data = instruction_context
                .try_borrow_instruction_account(1)?;
            let mut commitment_tree = load_commitment_tree(tree_data.get_data())
                .map_err(|_| InstructionError::InvalidAccountData)?;
            drop(tree_data);

            let nf_data = instruction_context
                .try_borrow_instruction_account(2)?;
            let mut nullifier_account = load_nullifier_set(nf_data.get_data())
                .unwrap_or_else(|_| NullifierSetAccount {
                    count: 0,
                    nullifiers: Vec::new(),
                    bloom_filter: None,
                });
            drop(nf_data);

            let anchor_data = instruction_context
                .try_borrow_instruction_account(3)?;
            let anchors = load_recent_anchors(anchor_data.get_data())
                .unwrap_or_else(|_| RecentAnchorsAccount {
                    anchors: vec![commitment_tree.root()],
                    position: 1,
                    max_size: MAX_RECENT_ANCHORS as u64,
                });
            drop(anchor_data);

            // Validate all spends
            for spend in &spends {
                if !anchors.contains(&spend.anchor) && spend.anchor != commitment_tree.root() {
                    return Err(InstructionError::Custom(2));
                }
                if nullifier_account.contains(&spend.nullifier) {
                    return Err(InstructionError::Custom(1));
                }
            }

            let mut nullifier_set = nullifier_account.to_set();
            let recent = anchors.to_anchors();

            process_shielded_transfer(
                &spends,
                &outputs,
                &binding_sig,
                &mut pool_state,
                &mut commitment_tree,
                &mut nullifier_set,
                Some(&recent),
            ).map_err(|e| InstructionError::from(e))?;

            for spend in &spends {
                nullifier_account.insert(spend.nullifier)
                    .map_err(|_| InstructionError::Custom(1))?;
            }

            // Save all state
            {
                let mut pool_data = instruction_context
                    .try_borrow_instruction_account(0)?;
                save_pool_state(&pool_state, pool_data.get_data_mut()?)
                    .map_err(|_| InstructionError::InvalidAccountData)?;
            }
            {
                let mut tree_data = instruction_context
                    .try_borrow_instruction_account(1)?;
                save_commitment_tree(&commitment_tree, tree_data.get_data_mut()?)
                    .map_err(|_| InstructionError::InvalidAccountData)?;
            }
            {
                let mut nf_data = instruction_context
                    .try_borrow_instruction_account(2)?;
                save_nullifier_set(&nullifier_account, nf_data.get_data_mut()?)
                    .map_err(|_| InstructionError::InvalidAccountData)?;
            }
            {
                let anchor_data = instruction_context
                    .try_borrow_instruction_account(3)?;
                let mut new_anchors = load_recent_anchors(anchor_data.get_data())
                    .unwrap_or(anchors);
                drop(anchor_data);
                new_anchors.add(commitment_tree.root());
                let mut anchor_data = instruction_context
                    .try_borrow_instruction_account(3)?;
                save_recent_anchors(&new_anchors, anchor_data.get_data_mut()?)
                    .map_err(|_| InstructionError::InvalidAccountData)?;
            }

            Ok(())
        }

        ShieldedInstruction::InitializePool { authority } => {
            // Accounts: 0=Pool, 1=Tree, 2=Nullifiers, 3=Anchors
            if num_accounts < 4 {
                return Err(InstructionError::MissingAccount);
            }

            // Initialize pool state
            let pool_state = ShieldedPoolState::new(authority);
            {
                let mut pool_data = instruction_context
                    .try_borrow_instruction_account(0)?;
                save_pool_state(&pool_state, pool_data.get_data_mut()?)
                    .map_err(|_| InstructionError::InvalidAccountData)?;
            }

            // Initialize empty commitment tree
            let tree = IncrementalMerkleTree::new();
            {
                let mut tree_data = instruction_context
                    .try_borrow_instruction_account(1)?;
                save_commitment_tree(&tree, tree_data.get_data_mut()?)
                    .map_err(|_| InstructionError::InvalidAccountData)?;
            }

            // Initialize empty nullifier set
            let nullifiers = NullifierSetAccount {
                count: 0,
                nullifiers: Vec::new(),
                bloom_filter: None,
            };
            {
                let mut nf_data = instruction_context
                    .try_borrow_instruction_account(2)?;
                save_nullifier_set(&nullifiers, nf_data.get_data_mut()?)
                    .map_err(|_| InstructionError::InvalidAccountData)?;
            }

            // Initialize anchors with the empty tree root
            let anchors = RecentAnchorsAccount {
                anchors: vec![tree.root()],
                position: 1,
                max_size: MAX_RECENT_ANCHORS as u64,
            };
            {
                let mut anchor_data = instruction_context
                    .try_borrow_instruction_account(3)?;
                save_recent_anchors(&anchors, anchor_data.get_data_mut()?)
                    .map_err(|_| InstructionError::InvalidAccountData)?;
            }

            Ok(())
        }

        // Token shielding (SPL tokens)
        ShieldedInstruction::ShieldToken { .. } => {
            // TODO: Implement SPL token shielding
            Err(InstructionError::InvalidInstructionData)
        }

        ShieldedInstruction::UnshieldToken { .. } => {
            // TODO: Implement SPL token unshielding
            Err(InstructionError::InvalidInstructionData)
        }

        // NFT shielding
        ShieldedInstruction::ShieldNFT { .. } => {
            // TODO: Implement NFT shielding
            Err(InstructionError::InvalidInstructionData)
        }

        ShieldedInstruction::UnshieldNFT { .. } => {
            // TODO: Implement NFT unshielding
            Err(InstructionError::InvalidInstructionData)
        }

        // Universal shielded transfer (multi-asset)
        ShieldedInstruction::UniversalShieldedTransfer { .. } => {
            // TODO: Implement universal shielded transfer
            Err(InstructionError::InvalidInstructionData)
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OutputDescription, ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE, GROTH_PROOF_SIZE};

    #[test]
    fn test_compute_units() {
        assert!(DEFAULT_COMPUTE_UNITS >= 500_000);
    }

    #[test]
    fn test_compute_budget_calculation() {
        // Test that calculate_compute_units scales with inputs
        let units_1_1 = calculate_compute_units(1, 1);
        let units_2_2 = calculate_compute_units(2, 2);

        // Should scale linearly
        assert!(units_2_2 > units_1_1);
        assert!(units_1_1 > 0);
    }

    #[test]
    fn test_shield_instruction_deserialization() {
        // This test verifies that Shield instructions can be deserialized
        // exactly as the native entrypoint does it
        let output = OutputDescription {
            cv: [1u8; 32],
            cmu: [2u8; 32],
            ephemeral_key: [3u8; 32],
            enc_ciphertext: [0u8; ENC_CIPHERTEXT_SIZE],
            out_ciphertext: [0u8; OUT_CIPHERTEXT_SIZE],
            zkproof: [0u8; GROTH_PROOF_SIZE],
        };

        let instruction = ShieldedInstruction::Shield {
            amount: 100_000_000,
            output,
        };

        // Serialize exactly as CLI does
        let data = borsh::to_vec(&instruction).expect("serialize failed");

        // Expected size: 1 (discriminant) + 8 (amount) + 32 + 32 + 32 + 580 + 80 + 192 = 957
        assert_eq!(data.len(), 957, "Shield instruction size mismatch");
        assert_eq!(data[0], 0, "Wrong discriminant");

        // Deserialize exactly as native.rs does
        let deserialized = ShieldedInstruction::try_from_slice(&data)
            .expect("deserialize failed - this is what native.rs does");

        match deserialized {
            ShieldedInstruction::Shield { amount, output: out } => {
                assert_eq!(amount, 100_000_000);
                assert_eq!(out.cv, [1u8; 32]);
                assert_eq!(out.cmu, [2u8; 32]);
            }
            _ => panic!("Wrong instruction type"),
        }
    }

    #[test]
    fn test_init_pool_deserialization() {
        let instruction = ShieldedInstruction::InitializePool {
            authority: [42u8; 32],
        };

        let data = borsh::to_vec(&instruction).expect("serialize failed");
        assert_eq!(data.len(), 33);
        assert_eq!(data[0], 3);

        let deserialized = ShieldedInstruction::try_from_slice(&data)
            .expect("deserialize failed");

        match deserialized {
            ShieldedInstruction::InitializePool { authority } => {
                assert_eq!(authority, [42u8; 32]);
            }
            _ => panic!("Wrong instruction type"),
        }
    }
}
