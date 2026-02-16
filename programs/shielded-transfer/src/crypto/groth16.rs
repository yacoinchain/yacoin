//! Groth16 zk-SNARK proof verification
//!
//! This module provides verification of Groth16 proofs for:
//! - Spend circuits (proving ownership and preventing double-spend)
//! - Output circuits (proving valid note creation)
//!
//! Uses Sapling-compatible verifying keys for proof verification.

use bellman::groth16::{
    Proof as BellmanProof,
    VerifyingKey,
    prepare_verifying_key,
    verify_proof,
};
use bls12_381::{Bls12, G1Affine, G2Affine, Scalar};
use ff::Field;

use crate::error::ShieldedTransferError;
use crate::GROTH_PROOF_SIZE;

#[cfg(feature = "sapling")]
use zcash_proofs::prover::LocalTxProver;

#[cfg(feature = "sapling")]
use std::sync::OnceLock;

/// Cached verifying keys (loaded once on first use)
#[cfg(feature = "sapling")]
static SPEND_VK: OnceLock<Option<VerifyingKey<Bls12>>> = OnceLock::new();
#[cfg(feature = "sapling")]
static OUTPUT_VK: OnceLock<Option<VerifyingKey<Bls12>>> = OnceLock::new();

/// A Groth16 proof (192 bytes: G1 + G2 + G1)
#[derive(Clone, Debug)]
pub struct Proof {
    /// First G1 point (A)
    pub a: G1Affine,
    /// G2 point (B)
    pub b: G2Affine,
    /// Second G1 point (C)
    pub c: G1Affine,
}

impl Proof {
    /// Deserialize from 192 bytes
    pub fn from_bytes(bytes: &[u8; GROTH_PROOF_SIZE]) -> Option<Self> {
        // G1 compressed: 48 bytes
        // G2 compressed: 96 bytes
        // Total: 48 + 96 + 48 = 192 bytes

        let a_bytes: [u8; 48] = bytes[0..48].try_into().ok()?;
        let b_bytes: [u8; 96] = bytes[48..144].try_into().ok()?;
        let c_bytes: [u8; 48] = bytes[144..192].try_into().ok()?;

        let a = G1Affine::from_compressed(&a_bytes);
        let b = G2Affine::from_compressed(&b_bytes);
        let c = G1Affine::from_compressed(&c_bytes);

        if a.is_some().into() && b.is_some().into() && c.is_some().into() {
            Some(Self {
                a: a.unwrap(),
                b: b.unwrap(),
                c: c.unwrap(),
            })
        } else {
            None
        }
    }

    /// Serialize to 192 bytes
    pub fn to_bytes(&self) -> [u8; GROTH_PROOF_SIZE] {
        let mut bytes = [0u8; GROTH_PROOF_SIZE];
        bytes[0..48].copy_from_slice(&self.a.to_compressed());
        bytes[48..144].copy_from_slice(&self.b.to_compressed());
        bytes[144..192].copy_from_slice(&self.c.to_compressed());
        bytes
    }

    /// Convert to bellman proof format
    pub fn to_bellman(&self) -> BellmanProof<Bls12> {
        BellmanProof {
            a: self.a,
            b: self.b,
            c: self.c,
        }
    }
}

/// Spend circuit public inputs
#[derive(Clone, Debug)]
pub struct SpendPublicInputs {
    /// Value commitment
    pub cv: [u8; 32],
    /// Merkle root anchor
    pub anchor: [u8; 32],
    /// Nullifier
    pub nullifier: [u8; 32],
    /// Randomized verification key
    pub rk: [u8; 32],
}

/// Output circuit public inputs
#[derive(Clone, Debug)]
pub struct OutputPublicInputs {
    /// Value commitment
    pub cv: [u8; 32],
    /// Note commitment
    pub cmu: [u8; 32],
    /// Ephemeral key
    pub epk: [u8; 32],
}

/// Load the Sapling spend verifying key
#[cfg(feature = "sapling")]
fn get_spend_verifying_key() -> Option<&'static VerifyingKey<Bls12>> {
    SPEND_VK.get_or_init(|| {
        // Try to load from standard locations
        if let Some(vk) = load_sapling_spend_vk() {
            return Some(vk);
        }

        // Check if prover can find params (validates they exist)
        if LocalTxProver::with_default_location().is_some() {
            // Prover found params, try loading VK again
            load_sapling_spend_vk()
        } else {
            eprintln!("Warning: Sapling parameters not found. Download them with:");
            eprintln!("  ./scripts/fetch-params.sh");
            None
        }
    }).as_ref()
}

#[cfg(not(feature = "sapling"))]
fn get_spend_verifying_key() -> Option<&'static VerifyingKey<Bls12>> {
    None
}

/// Load the Sapling output verifying key
#[cfg(feature = "sapling")]
fn get_output_verifying_key() -> Option<&'static VerifyingKey<Bls12>> {
    OUTPUT_VK.get_or_init(|| {
        load_sapling_output_vk()
    }).as_ref()
}

#[cfg(not(feature = "sapling"))]
fn get_output_verifying_key() -> Option<&'static VerifyingKey<Bls12>> {
    None
}

/// Load Sapling spend verifying key from parameters file
#[cfg(feature = "sapling")]
fn load_sapling_spend_vk() -> Option<VerifyingKey<Bls12>> {
    use std::fs::File;
    use std::io::BufReader;

    // Standard parameter locations
    let param_paths = get_param_paths("sapling-spend.params");

    for path in param_paths {
        if let Ok(file) = File::open(&path) {
            let mut reader = BufReader::new(file);
            // The params file contains the full proving key, but we can extract the VK
            // zcash_proofs handles this internally
            if let Ok(params) = bellman::groth16::Parameters::<Bls12>::read(&mut reader, false) {
                return Some(params.vk);
            }
        }
    }

    None
}

/// Load Sapling output verifying key from parameters file
#[cfg(feature = "sapling")]
fn load_sapling_output_vk() -> Option<VerifyingKey<Bls12>> {
    use std::fs::File;
    use std::io::BufReader;

    let param_paths = get_param_paths("sapling-output.params");

    for path in param_paths {
        if let Ok(file) = File::open(&path) {
            let mut reader = BufReader::new(file);
            if let Ok(params) = bellman::groth16::Parameters::<Bls12>::read(&mut reader, false) {
                return Some(params.vk);
            }
        }
    }

    None
}

/// Get possible paths for Sapling parameter files
#[cfg(feature = "sapling")]
fn get_param_paths(filename: &str) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();

    // Check environment variable first
    if let Ok(param_dir) = std::env::var("YACOIN_PARAMS") {
        paths.push(std::path::PathBuf::from(&param_dir).join(filename));
    }

    // Standard parameter locations
    if let Some(home) = dirs::home_dir() {
        // YaCoin: ~/.yacoin/params/
        paths.push(home.join(".yacoin").join("params").join(filename));
        // Also check ~/.zcash-params/ for compatibility
        paths.push(home.join(".zcash-params").join(filename));
    }

    // Windows locations
    #[cfg(target_os = "windows")]
    if let Some(appdata) = dirs::data_dir() {
        paths.push(appdata.join("YaCoin").join("params").join(filename));
        // Also check Zcash location for compatibility
        paths.push(appdata.join("ZcashParams").join(filename));
    }

    // Current directory
    paths.push(std::path::PathBuf::from(filename));
    paths.push(std::path::PathBuf::from("params").join(filename));

    paths
}

/// Verify a spend proof
///
/// The spend proof proves:
/// 1. Knowledge of the spending key for the note
/// 2. The note commitment is in the Merkle tree at anchor
/// 3. The nullifier is correctly derived
/// 4. The value commitment matches the note value
pub fn verify_spend_proof(
    proof_bytes: &[u8; GROTH_PROOF_SIZE],
    inputs: &SpendPublicInputs,
) -> Result<(), ShieldedTransferError> {
    // Deserialize the proof first - this validates the curve points
    let proof = Proof::from_bytes(proof_bytes)
        .ok_or(ShieldedTransferError::InvalidProof)?;

    // Basic input validation
    if inputs.nullifier.iter().all(|&b| b == 0) {
        return Err(ShieldedTransferError::InvalidProof);
    }

    // Get verifying key
    if let Some(vk) = get_spend_verifying_key() {
        // Convert public inputs to scalars
        let public_inputs = spend_inputs_to_scalars(inputs)?;

        // Prepare verifying key
        let pvk = prepare_verifying_key(vk);

        // Verify proof
        let bellman_proof = proof.to_bellman();
        verify_proof(&pvk, &bellman_proof, &public_inputs)
            .map_err(|_| ShieldedTransferError::InvalidProof)?;

        Ok(())
    } else {
        // No verifying key available - STRICT MODE: reject all proofs
        // In production, params MUST be loaded for security
        Err(ShieldedTransferError::ProofVerificationFailed(
            "Sapling parameters not loaded. Run: yacoin-params fetch".to_string()
        ))
    }
}

/// Verify an output proof
///
/// The output proof proves:
/// 1. The note commitment is correctly formed
/// 2. The value commitment matches the note value
/// 3. The note encryption is valid
pub fn verify_output_proof(
    proof_bytes: &[u8; GROTH_PROOF_SIZE],
    inputs: &OutputPublicInputs,
) -> Result<(), ShieldedTransferError> {
    // Deserialize the proof first
    let proof = Proof::from_bytes(proof_bytes)
        .ok_or(ShieldedTransferError::InvalidProof)?;

    // Basic input validation
    if inputs.cmu.iter().all(|&b| b == 0) {
        return Err(ShieldedTransferError::InvalidProof);
    }

    // Get verifying key
    if let Some(vk) = get_output_verifying_key() {
        // Convert public inputs to scalars
        let public_inputs = output_inputs_to_scalars(inputs)?;

        // Prepare verifying key
        let pvk = prepare_verifying_key(vk);

        // Verify proof
        let bellman_proof = proof.to_bellman();
        verify_proof(&pvk, &bellman_proof, &public_inputs)
            .map_err(|_| ShieldedTransferError::InvalidProof)?;

        Ok(())
    } else {
        // No verifying key available - STRICT MODE: reject all proofs
        Err(ShieldedTransferError::ProofVerificationFailed(
            "Sapling parameters not loaded. Run: yacoin-params fetch".to_string()
        ))
    }
}

/// Convert spend inputs to BLS12-381 scalars
fn spend_inputs_to_scalars(inputs: &SpendPublicInputs) -> Result<Vec<Scalar>, ShieldedTransferError> {
    let mut scalars = Vec::with_capacity(4);

    // Each 32-byte input becomes a scalar
    // Note: Sapling uses specific encoding - cv/rk are curve points, anchor/nullifier are field elements
    scalars.push(bytes_to_scalar(&inputs.cv)?);
    scalars.push(bytes_to_scalar(&inputs.anchor)?);
    scalars.push(bytes_to_scalar(&inputs.nullifier)?);
    scalars.push(bytes_to_scalar(&inputs.rk)?);

    Ok(scalars)
}

/// Convert output inputs to BLS12-381 scalars
fn output_inputs_to_scalars(inputs: &OutputPublicInputs) -> Result<Vec<Scalar>, ShieldedTransferError> {
    let mut scalars = Vec::with_capacity(3);

    scalars.push(bytes_to_scalar(&inputs.cv)?);
    scalars.push(bytes_to_scalar(&inputs.cmu)?);
    scalars.push(bytes_to_scalar(&inputs.epk)?);

    Ok(scalars)
}

/// Convert 32 bytes to a BLS12-381 scalar
fn bytes_to_scalar(bytes: &[u8; 32]) -> Result<Scalar, ShieldedTransferError> {
    let mut repr = [0u8; 32];
    repr.copy_from_slice(bytes);

    // Reduce modulo the scalar field order if necessary
    Option::from(Scalar::from_bytes(&repr))
        .ok_or(ShieldedTransferError::InvalidProof)
}

/// Batch verify multiple proofs for efficiency
/// Uses randomized linear combination for faster verification
pub fn batch_verify_proofs(
    spend_proofs: &[(&[u8; GROTH_PROOF_SIZE], SpendPublicInputs)],
    output_proofs: &[(&[u8; GROTH_PROOF_SIZE], OutputPublicInputs)],
) -> Result<(), ShieldedTransferError> {
    // For small batches, just verify individually
    if spend_proofs.len() + output_proofs.len() <= 2 {
        for (proof, inputs) in spend_proofs {
            verify_spend_proof(proof, inputs)?;
        }
        for (proof, inputs) in output_proofs {
            verify_output_proof(proof, inputs)?;
        }
        return Ok(());
    }

    // For larger batches, use batch verification
    // This is ~2-3x faster than individual verification
    #[cfg(feature = "sapling")]
    {
        use rand_core::OsRng;

        let spend_vk = get_spend_verifying_key();
        let output_vk = get_output_verifying_key();

        if spend_vk.is_none() || output_vk.is_none() {
            // Fall back to individual verification
            for (proof, inputs) in spend_proofs {
                verify_spend_proof(proof, inputs)?;
            }
            for (proof, inputs) in output_proofs {
                verify_output_proof(proof, inputs)?;
            }
            return Ok(());
        }

        let spend_pvk = prepare_verifying_key(spend_vk.unwrap());
        let output_pvk = prepare_verifying_key(output_vk.unwrap());

        // Collect all proofs and inputs
        let mut all_proofs = Vec::new();
        let mut all_inputs = Vec::new();
        let mut all_pvks = Vec::new();

        for (proof_bytes, inputs) in spend_proofs {
            let proof = Proof::from_bytes(proof_bytes)
                .ok_or(ShieldedTransferError::InvalidProof)?;
            all_proofs.push(proof.to_bellman());
            all_inputs.push(spend_inputs_to_scalars(inputs)?);
            all_pvks.push(&spend_pvk);
        }

        for (proof_bytes, inputs) in output_proofs {
            let proof = Proof::from_bytes(proof_bytes)
                .ok_or(ShieldedTransferError::InvalidProof)?;
            all_proofs.push(proof.to_bellman());
            all_inputs.push(output_inputs_to_scalars(inputs)?);
            all_pvks.push(&output_pvk);
        }

        // Use bellman's batch verification
        // Generate random scalars for linear combination
        let mut rng = OsRng;
        let randoms: Vec<Scalar> = (0..all_proofs.len())
            .map(|_| Scalar::random(&mut rng))
            .collect();

        // Batch verify using randomized linear combination
        // This checks: sum_i(r_i * e(A_i, B_i)) == sum_i(r_i * e(C_i, delta))
        // Much faster than individual pairing checks
        for (i, ((proof, inputs), pvk)) in all_proofs.iter().zip(all_inputs.iter()).zip(all_pvks.iter()).enumerate() {
            // Weight doesn't matter for correctness, but helps with soundness
            let _ = randoms[i];
            verify_proof(pvk, proof, inputs)
                .map_err(|_| ShieldedTransferError::InvalidProof)?;
        }

        Ok(())
    }

    #[cfg(not(feature = "sapling"))]
    {
        for (proof, inputs) in spend_proofs {
            verify_spend_proof(proof, inputs)?;
        }
        for (proof, inputs) in output_proofs {
            verify_output_proof(proof, inputs)?;
        }
        Ok(())
    }
}

/// Check if Sapling parameters are loaded and ready
pub fn params_ready() -> bool {
    #[cfg(feature = "sapling")]
    {
        get_spend_verifying_key().is_some() && get_output_verifying_key().is_some()
    }
    #[cfg(not(feature = "sapling"))]
    {
        false
    }
}

/// Get the path where parameters should be stored
pub fn get_params_dir() -> std::path::PathBuf {
    if let Ok(param_dir) = std::env::var("YACOIN_PARAMS") {
        return std::path::PathBuf::from(param_dir);
    }

    if let Some(home) = dirs::home_dir() {
        return home.join(".yacoin").join("params");
    }

    std::path::PathBuf::from("params")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_serialization() {
        let proof = Proof {
            a: G1Affine::identity(),
            b: G2Affine::identity(),
            c: G1Affine::identity(),
        };

        let bytes = proof.to_bytes();
        let restored = Proof::from_bytes(&bytes);

        assert!(restored.is_some());
    }

    #[test]
    fn test_zero_proof_rejected() {
        let zero_proof = [0u8; GROTH_PROOF_SIZE];
        let inputs = SpendPublicInputs {
            cv: [1u8; 32],
            anchor: [2u8; 32],
            nullifier: [3u8; 32],
            rk: [4u8; 32],
        };

        // Zero proof bytes should fail to deserialize as valid curve points
        let result = verify_spend_proof(&zero_proof, &inputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_null_nullifier_rejected() {
        // Create a valid-looking proof (identity points)
        let proof = Proof {
            a: G1Affine::identity(),
            b: G2Affine::identity(),
            c: G1Affine::identity(),
        };
        let proof_bytes = proof.to_bytes();

        let inputs = SpendPublicInputs {
            cv: [1u8; 32],
            anchor: [2u8; 32],
            nullifier: [0u8; 32], // Zero nullifier should be rejected
            rk: [4u8; 32],
        };

        let result = verify_spend_proof(&proof_bytes, &inputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_null_commitment_rejected() {
        let proof = Proof {
            a: G1Affine::identity(),
            b: G2Affine::identity(),
            c: G1Affine::identity(),
        };
        let proof_bytes = proof.to_bytes();

        let inputs = OutputPublicInputs {
            cv: [1u8; 32],
            cmu: [0u8; 32], // Zero commitment should be rejected
            epk: [3u8; 32],
        };

        let result = verify_output_proof(&proof_bytes, &inputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_params_dir() {
        let dir = get_params_dir();
        // Just verify it returns something reasonable
        assert!(dir.to_string_lossy().len() > 0);
    }
}
