//! Groth16 zk-SNARK Verification for YaCoin Shielded Transactions
//!
//! This module provides native Groth16 proof verification using BLS12-381 pairings.
//! Verification is optimized for Sapling-style proofs (spend and output circuits).
//!
//! Groth16 verification equation:
//! e(A, B) = e(α, β) * e(L, γ) * e(C, δ)
//!
//! Where:
//! - (A, B, C) are the proof elements
//! - (α, β, γ, δ) are verification key elements
//! - L = sum(ai * Li) is the linear combination of public inputs

#![allow(clippy::arithmetic_side_effects)]

use {
    crate::{
        encoding::{Endianness, PodG1Point, PodG2Point},
        Version,
    },
    blstrs::{Bls12, G1Affine, G1Projective, G2Prepared, Gt, Scalar},
    group::{Curve, Group},
    pairing::{MillerLoopResult, MultiMillerLoop},
};

/// Maximum number of public inputs for Groth16 verification
pub const MAX_PUBLIC_INPUTS: usize = 8;

/// Groth16 proof structure (A, B, C points)
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PodGroth16Proof {
    /// G1 element A (96 bytes uncompressed)
    pub a: PodG1Point,
    /// G2 element B (192 bytes uncompressed)
    pub b: PodG2Point,
    /// G1 element C (96 bytes uncompressed)
    pub c: PodG1Point,
}

/// Groth16 verification key (prepared for efficient verification)
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PodGroth16VerifyingKey {
    /// α in G1
    pub alpha_g1: PodG1Point,
    /// β in G2
    pub beta_g2: PodG2Point,
    /// γ in G2
    pub gamma_g2: PodG2Point,
    /// δ in G2
    pub delta_g2: PodG2Point,
    /// Number of public inputs (IC length - 1)
    pub num_public_inputs: u8,
}

/// Verify a Groth16 proof with the given verification key and public inputs
///
/// Returns `true` if the proof is valid, `false` otherwise.
///
/// The verification checks:
/// e(-A, B) * e(α, β) * e(L, γ) * e(C, δ) = 1
///
/// Where L = IC[0] + sum(public_input[i] * IC[i+1])
pub fn bls12_381_groth16_verify(
    _version: Version,
    proof: &PodGroth16Proof,
    vk: &PodGroth16VerifyingKey,
    ic_points: &[PodG1Point],
    public_inputs: &[[u8; 32]],
    endianness: Endianness,
) -> Option<bool> {
    // Validate inputs
    if public_inputs.len() > MAX_PUBLIC_INPUTS {
        return None;
    }

    // IC should have public_inputs.len() + 1 elements
    if ic_points.len() != public_inputs.len() + 1 {
        return None;
    }

    // Parse proof elements
    let a = proof.a.to_affine(endianness)?;
    let b = proof.b.to_affine(endianness)?;
    let c = proof.c.to_affine(endianness)?;

    // Parse verification key elements
    let alpha = vk.alpha_g1.to_affine(endianness)?;
    let beta = vk.beta_g2.to_affine(endianness)?;
    let gamma = vk.gamma_g2.to_affine(endianness)?;
    let delta = vk.delta_g2.to_affine(endianness)?;

    // Compute L = IC[0] + sum(public_input[i] * IC[i+1])
    let mut l: G1Projective = ic_points[0].to_affine(endianness)?.into();

    for (i, input) in public_inputs.iter().enumerate() {
        let ic_point = ic_points[i + 1].to_affine(endianness)?;
        let scalar = bytes_to_scalar(input)?;
        let term: G1Projective = ic_point * scalar;
        l = l + term;
    }

    let l_affine: G1Affine = l.to_affine();

    // Negate A for the pairing equation
    let neg_a = -a;

    // Prepare G2 points
    let b_prepared = G2Prepared::from(b);
    let beta_prepared = G2Prepared::from(beta);
    let gamma_prepared = G2Prepared::from(gamma);
    let delta_prepared = G2Prepared::from(delta);

    // Compute multi-pairing: e(-A, B) * e(α, β) * e(L, γ) * e(C, δ)
    let pairs: Vec<(&G1Affine, &G2Prepared)> = vec![
        (&neg_a, &b_prepared),
        (&alpha, &beta_prepared),
        (&l_affine, &gamma_prepared),
        (&c, &delta_prepared),
    ];

    let miller_result = Bls12::multi_miller_loop(&pairs);
    let result = miller_result.final_exponentiation();

    // Proof is valid if result equals identity
    Some(result == Gt::identity())
}

// Note: Prepared verification (with pre-computed e(α, β)) is not yet implemented.
// The current verification function computes all 4 pairings together which is
// efficient enough for most use cases.

/// Convert 32-byte scalar to blstrs Scalar
fn bytes_to_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    // Input is in little-endian, reverse to big-endian for from_bytes_be
    let mut be_bytes = *bytes;
    be_bytes.reverse();

    // Try to create scalar from bytes (big-endian)
    let scalar_opt: Option<Scalar> = Scalar::from_bytes_be(&be_bytes).into();
    scalar_opt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_public_inputs() {
        assert_eq!(MAX_PUBLIC_INPUTS, 8);
    }

    #[test]
    fn test_bytes_to_scalar() {
        let zero = [0u8; 32];
        let scalar = bytes_to_scalar(&zero);
        assert!(scalar.is_some());
    }

    #[test]
    fn test_proof_structure_size() {
        use std::mem::size_of;
        // A (96) + B (192) + C (96) = 384 bytes
        assert_eq!(size_of::<PodGroth16Proof>(), 384);
    }
}
