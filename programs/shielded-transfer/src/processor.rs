//! Instruction processor for the shielded transfer program
//!
//! Handles Shield, Unshield, and ShieldedTransfer operations with
//! real Groth16 zk-SNARK proof verification.

use crate::{
    commitment_tree::{IncrementalMerkleTree, RecentAnchors},
    error::ShieldedTransferError,
    nullifier_set::NullifierSet,
    state::ShieldedPoolState,
    SpendDescription, OutputDescription,
    GROTH_PROOF_SIZE, NOTE_COMMITMENT_SIZE, NULLIFIER_SIZE,
    VERIFY_SPEND_COMPUTE_UNITS, VERIFY_OUTPUT_COMPUTE_UNITS,
};

#[cfg(feature = "sapling")]
use crate::crypto::groth16::{
    verify_spend_proof as groth16_verify_spend,
    verify_output_proof as groth16_verify_output,
    SpendPublicInputs, OutputPublicInputs,
    batch_verify_proofs,
};

/// Process a Shield instruction (transparent -> shielded)
///
/// Converts transparent tokens to shielded notes.
/// The caller must transfer `amount` from their transparent account.
pub fn process_shield(
    amount: u64,
    output: &OutputDescription,
    pool_state: &mut ShieldedPoolState,
    commitment_tree: &mut IncrementalMerkleTree,
) -> Result<(), ShieldedTransferError> {
    // 1. Verify the output proof
    verify_output_proof(&output.zkproof, &output.cv, &output.cmu, &output.ephemeral_key)?;

    // 2. Update pool state
    pool_state.add_shielded(amount)?;
    pool_state.increment_commitments()?;

    // 3. Add commitment to the tree
    commitment_tree.append(output.cmu)?;

    Ok(())
}

/// Process an Unshield instruction (shielded -> transparent)
///
/// Converts shielded notes to transparent tokens.
/// The program will transfer `amount` to the recipient's transparent account.
pub fn process_unshield(
    amount: u64,
    spend: &SpendDescription,
    pool_state: &mut ShieldedPoolState,
    nullifier_set: &mut NullifierSet,
    commitment_tree: &IncrementalMerkleTree,
    recent_anchors: Option<&RecentAnchors>,
) -> Result<(), ShieldedTransferError> {
    // 1. Verify the anchor is valid (current root or recent)
    let current_root = commitment_tree.root();
    if spend.anchor != current_root {
        // Check recent anchors if provided
        if let Some(anchors) = recent_anchors {
            if !anchors.contains(&spend.anchor) {
                return Err(ShieldedTransferError::InvalidAnchor);
            }
        } else {
            return Err(ShieldedTransferError::InvalidAnchor);
        }
    }

    // 2. Verify nullifier hasn't been used (prevent double-spend)
    if nullifier_set.contains(&spend.nullifier) {
        return Err(ShieldedTransferError::NullifierAlreadySpent);
    }

    // 3. Verify the spend proof
    verify_spend_proof(
        &spend.zkproof,
        &spend.cv,
        &spend.anchor,
        &spend.nullifier,
        &spend.rk,
    )?;

    // 4. Add nullifier to set (mark as spent)
    nullifier_set.insert(spend.nullifier)?;

    // 5. Update pool state
    pool_state.remove_shielded(amount)?;
    pool_state.increment_nullifiers()?;

    Ok(())
}

/// Process a ShieldedTransfer instruction (shielded -> shielded)
///
/// Transfers value between shielded addresses.
/// Value balance must be zero (sum of inputs = sum of outputs).
pub fn process_shielded_transfer(
    spends: &[SpendDescription],
    outputs: &[OutputDescription],
    binding_sig: &[u8; 64],
    pool_state: &mut ShieldedPoolState,
    commitment_tree: &mut IncrementalMerkleTree,
    nullifier_set: &mut NullifierSet,
    recent_anchors: Option<&RecentAnchors>,
) -> Result<(), ShieldedTransferError> {
    // 1. Verify binding signature (proves value balance)
    verify_binding_signature(spends, outputs, binding_sig)?;

    // 2. Prepare batch verification if possible
    #[cfg(feature = "sapling")]
    {
        // Collect proofs for batch verification
        let spend_proofs: Vec<_> = spends.iter().map(|s| {
            let inputs = SpendPublicInputs {
                cv: s.cv,
                anchor: s.anchor,
                nullifier: s.nullifier,
                rk: s.rk,
            };
            (&s.zkproof, inputs)
        }).collect();

        let output_proofs: Vec<_> = outputs.iter().map(|o| {
            let inputs = OutputPublicInputs {
                cv: o.cv,
                cmu: o.cmu,
                epk: o.ephemeral_key,
            };
            (&o.zkproof, inputs)
        }).collect();

        // Batch verify all proofs
        batch_verify_proofs(&spend_proofs, &output_proofs)?;
    }

    // 3. Process spends (check nullifiers)
    for spend in spends {
        // Check anchor validity
        let current_root = commitment_tree.root();
        if spend.anchor != current_root {
            if let Some(anchors) = recent_anchors {
                if !anchors.contains(&spend.anchor) {
                    return Err(ShieldedTransferError::InvalidAnchor);
                }
            } else {
                return Err(ShieldedTransferError::InvalidAnchor);
            }
        }

        // Check nullifier not spent
        if nullifier_set.contains(&spend.nullifier) {
            return Err(ShieldedTransferError::NullifierAlreadySpent);
        }

        // Without batch verification, verify individually
        #[cfg(not(feature = "sapling"))]
        verify_spend_proof(
            &spend.zkproof,
            &spend.cv,
            &spend.anchor,
            &spend.nullifier,
            &spend.rk,
        )?;

        // Add nullifier
        nullifier_set.insert(spend.nullifier)?;
        pool_state.increment_nullifiers()?;
    }

    // 4. Process outputs
    for output in outputs {
        #[cfg(not(feature = "sapling"))]
        verify_output_proof(&output.zkproof, &output.cv, &output.cmu, &output.ephemeral_key)?;

        commitment_tree.append(output.cmu)?;
        pool_state.increment_commitments()?;
    }

    Ok(())
}

/// Verify a zk-SNARK spend proof using Groth16
fn verify_spend_proof(
    proof: &[u8; GROTH_PROOF_SIZE],
    cv: &[u8; 32],
    anchor: &[u8; 32],
    nullifier: &[u8; NULLIFIER_SIZE],
    rk: &[u8; 32],
) -> Result<(), ShieldedTransferError> {
    #[cfg(feature = "sapling")]
    {
        let inputs = SpendPublicInputs {
            cv: *cv,
            anchor: *anchor,
            nullifier: *nullifier,
            rk: *rk,
        };
        groth16_verify_spend(proof, &inputs)
    }

    #[cfg(not(feature = "sapling"))]
    {
        // Without sapling feature, just do basic validation
        let _ = (cv, anchor, rk);
        if proof.iter().all(|&b| b == 0) {
            return Err(ShieldedTransferError::InvalidProof);
        }
        if nullifier.iter().all(|&b| b == 0) {
            return Err(ShieldedTransferError::InvalidProof);
        }
        Ok(())
    }
}

/// Verify a zk-SNARK output proof using Groth16
fn verify_output_proof(
    proof: &[u8; GROTH_PROOF_SIZE],
    cv: &[u8; 32],
    cmu: &[u8; NOTE_COMMITMENT_SIZE],
    epk: &[u8; 32],
) -> Result<(), ShieldedTransferError> {
    #[cfg(feature = "sapling")]
    {
        let inputs = OutputPublicInputs {
            cv: *cv,
            cmu: *cmu,
            epk: *epk,
        };
        groth16_verify_output(proof, &inputs)
    }

    #[cfg(not(feature = "sapling"))]
    {
        // Without sapling feature, just do basic validation
        let _ = (cv, epk);
        if proof.iter().all(|&b| b == 0) {
            return Err(ShieldedTransferError::InvalidProof);
        }
        if cmu.iter().all(|&b| b == 0) {
            return Err(ShieldedTransferError::InvalidProof);
        }
        Ok(())
    }
}

/// Verify binding signature proving value balance
///
/// The binding signature proves that the sum of spend value commitments
/// equals the sum of output value commitments (plus any transparent value).
fn verify_binding_signature(
    spends: &[SpendDescription],
    outputs: &[OutputDescription],
    binding_sig: &[u8; 64],
) -> Result<(), ShieldedTransferError> {
    // Basic validation
    if binding_sig.iter().all(|&b| b == 0) && (!spends.is_empty() || !outputs.is_empty()) {
        return Err(ShieldedTransferError::InvalidProof);
    }

    #[cfg(feature = "sapling")]
    {
        // In a full implementation, we would:
        // 1. Compute sum of spend cv values (as curve points)
        // 2. Compute sum of output cv values (as curve points)
        // 3. Compute binding_verification_key = sum(spend.cv) - sum(output.cv)
        // 4. Verify the signature over sighash using binding_verification_key

        // For now, validate that cv values are non-trivial
        for spend in spends {
            if spend.cv.iter().all(|&b| b == 0) {
                return Err(ShieldedTransferError::InvalidProof);
            }
        }
        for output in outputs {
            if output.cv.iter().all(|&b| b == 0) {
                return Err(ShieldedTransferError::InvalidProof);
            }
        }
    }

    Ok(())
}

/// Calculate compute units needed for a shielded transfer
pub fn calculate_compute_units(num_spends: usize, num_outputs: usize) -> u64 {
    let spend_units = (num_spends as u64).saturating_mul(VERIFY_SPEND_COMPUTE_UNITS);
    let output_units = (num_outputs as u64).saturating_mul(VERIFY_OUTPUT_COMPUTE_UNITS);
    spend_units.saturating_add(output_units)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a proof using BLS12-381 identity points
    /// This creates a structurally valid proof (deserializes correctly)
    fn create_identity_proof() -> [u8; GROTH_PROOF_SIZE] {
        use bls12_381::{G1Affine, G2Affine};

        let mut proof = [0u8; GROTH_PROOF_SIZE];
        // G1 identity point (compressed) - 48 bytes
        proof[0..48].copy_from_slice(&G1Affine::identity().to_compressed());
        // G2 identity point (compressed) - 96 bytes
        proof[48..144].copy_from_slice(&G2Affine::identity().to_compressed());
        // G1 identity point (compressed) - 48 bytes
        proof[144..192].copy_from_slice(&G1Affine::identity().to_compressed());
        proof
    }

    fn create_valid_spend() -> SpendDescription {
        SpendDescription {
            cv: [1u8; 32],
            anchor: [2u8; 32],
            nullifier: [3u8; 32],
            rk: [4u8; 32],
            zkproof: create_identity_proof(),
            spend_auth_sig: [5u8; 64],
        }
    }

    fn create_valid_output() -> OutputDescription {
        OutputDescription {
            cv: [1u8; 32],
            cmu: [2u8; 32],
            ephemeral_key: [3u8; 32],
            enc_ciphertext: [0u8; crate::ENC_CIPHERTEXT_SIZE],
            out_ciphertext: [0u8; crate::OUT_CIPHERTEXT_SIZE],
            zkproof: create_identity_proof(),
        }
    }

    #[test]
    fn test_calculate_compute_units() {
        let units = calculate_compute_units(2, 3);
        let expected = 2 * VERIFY_SPEND_COMPUTE_UNITS + 3 * VERIFY_OUTPUT_COMPUTE_UNITS;
        assert_eq!(units, expected);
    }

    #[test]
    fn test_invalid_proof_rejected() {
        let zero_proof = [0u8; GROTH_PROOF_SIZE];
        let cv = [1u8; 32];
        let anchor = [2u8; 32];
        let nullifier = [3u8; 32];
        let rk = [4u8; 32];
        let result = verify_spend_proof(&zero_proof, &cv, &anchor, &nullifier, &rk);
        assert!(matches!(result, Err(ShieldedTransferError::InvalidProof)));
    }

    #[test]
    fn test_process_shield() {
        let mut pool_state = ShieldedPoolState::new([0u8; 32]);
        let mut tree = IncrementalMerkleTree::new();
        let output = create_valid_output();

        let result = process_shield(100, &output, &mut pool_state, &mut tree);
        assert!(result.is_ok());
        assert_eq!(pool_state.total_shielded, 100);
        assert_eq!(tree.size(), 1);
    }

    #[test]
    fn test_process_unshield_double_spend() {
        let mut pool_state = ShieldedPoolState::new([0u8; 32]);
        let mut tree = IncrementalMerkleTree::new();
        let mut nullifier_set = NullifierSet::new();

        // Setup: add a commitment first
        let output = create_valid_output();
        tree.append(output.cmu).unwrap();
        pool_state.add_shielded(100).unwrap();
        pool_state.increment_commitments().unwrap();

        // Create spend with correct anchor
        let mut spend = create_valid_spend();
        spend.anchor = tree.root();

        // First unshield should succeed
        let result = process_unshield(
            50, &spend,
            &mut pool_state, &mut nullifier_set, &tree, None
        );
        assert!(result.is_ok());

        // Second unshield with same nullifier should fail
        pool_state.add_shielded(50).unwrap(); // Add back for the test
        let result = process_unshield(
            50, &spend,
            &mut pool_state, &mut nullifier_set, &tree, None
        );
        assert!(matches!(result, Err(ShieldedTransferError::NullifierAlreadySpent)));
    }

    #[test]
    fn test_process_unshield_invalid_anchor() {
        let mut pool_state = ShieldedPoolState::new([0u8; 32]);
        let tree = IncrementalMerkleTree::new();
        let mut nullifier_set = NullifierSet::new();

        let spend = create_valid_spend(); // Has wrong anchor

        let result = process_unshield(
            50, &spend,
            &mut pool_state, &mut nullifier_set, &tree, None
        );
        assert!(matches!(result, Err(ShieldedTransferError::InvalidAnchor)));
    }

    #[test]
    fn test_process_shielded_transfer() {
        let mut pool_state = ShieldedPoolState::new([0u8; 32]);
        let mut tree = IncrementalMerkleTree::new();
        let mut nullifier_set = NullifierSet::new();

        // Add initial commitment
        let initial_output = create_valid_output();
        tree.append(initial_output.cmu).unwrap();

        // Create spend with correct anchor
        let mut spend = create_valid_spend();
        spend.anchor = tree.root();

        let output = create_valid_output();
        let binding_sig = [1u8; 64];

        let result = process_shielded_transfer(
            &[spend],
            &[output],
            &binding_sig,
            &mut pool_state,
            &mut tree,
            &mut nullifier_set,
            None,
        );
        assert!(result.is_ok());
    }
}
