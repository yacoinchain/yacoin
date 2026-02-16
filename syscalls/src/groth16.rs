//! Groth16 zk-SNARK Verification Syscall
//!
//! This syscall provides native Groth16 proof verification for YaCoin shielded transactions.
//! Uses BLS12-381 pairings for efficient verification at ~75k compute units.

use super::*;

/// Result code for successful operations
pub const SUCCESS: u64 = 0;

/// Result code for invalid proof
pub const INVALID_PROOF: u64 = 1;

/// Result code for invalid inputs
pub const INVALID_INPUTS: u64 = 2;

declare_builtin_function!(
    /// Verify a Groth16 proof using BLS12-381 pairings
    ///
    /// Arguments:
    /// - proof_addr: Address of proof data (A, B, C points = 384 bytes)
    /// - vk_addr: Address of verification key (α, β, γ, δ + IC points)
    /// - public_inputs_addr: Address of public inputs array
    /// - num_public_inputs: Number of public inputs (0-8)
    /// - endianness: 0 = little-endian, 1 = big-endian
    ///
    /// Returns:
    /// - 0: Proof is valid
    /// - 1: Proof is invalid
    /// - 2: Invalid inputs (malformed data)
    SyscallGroth16Verify,
    fn rust(
        invoke_context: &mut InvokeContext,
        proof_addr: u64,
        vk_addr: u64,
        public_inputs_addr: u64,
        num_public_inputs: u64,
        endianness: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        use agave_bls12_381::{
            bls12_381_groth16_verify, Endianness, PodG1Point,
            PodGroth16Proof, PodGroth16VerifyingKey, Version, MAX_PUBLIC_INPUTS,
        };

        // Validate number of public inputs
        if num_public_inputs > MAX_PUBLIC_INPUTS as u64 {
            return Ok(INVALID_INPUTS);
        }

        // Calculate compute cost
        let execution_cost = invoke_context.get_execution_cost();
        let cost = execution_cost.groth16_verify_cost
            .saturating_add(
                execution_cost.groth16_per_public_input_cost
                    .saturating_mul(num_public_inputs)
            );
        consume_compute_meter(invoke_context, cost)?;

        // Determine endianness
        let endian = if endianness == 0 {
            Endianness::LE
        } else {
            Endianness::BE
        };

        // Read proof from memory (384 bytes: A=96, B=192, C=96)
        let proof = translate_type::<PodGroth16Proof>(
            memory_mapping,
            proof_addr,
            invoke_context.get_check_aligned(),
        )?;

        // Read verification key from memory
        let vk = translate_type::<PodGroth16VerifyingKey>(
            memory_mapping,
            vk_addr,
            invoke_context.get_check_aligned(),
        )?;

        // IC points follow the verification key
        // IC size = (num_public_inputs + 1) * 96 bytes
        let ic_count = num_public_inputs.saturating_add(1);
        let ic_offset = size_of::<PodGroth16VerifyingKey>() as u64;
        let ic_addr = vk_addr.saturating_add(ic_offset);

        let ic_points = translate_slice::<PodG1Point>(
            memory_mapping,
            ic_addr,
            ic_count,
            invoke_context.get_check_aligned(),
        )?;

        // Read public inputs (32 bytes each)
        let public_inputs = if num_public_inputs > 0 {
            translate_slice::<[u8; 32]>(
                memory_mapping,
                public_inputs_addr,
                num_public_inputs,
                invoke_context.get_check_aligned(),
            )?
        } else {
            &[]
        };

        // Verify the proof
        match bls12_381_groth16_verify(
            Version::V0,
            proof,
            vk,
            ic_points,
            public_inputs,
            endian,
        ) {
            Some(true) => Ok(SUCCESS),
            Some(false) => Ok(INVALID_PROOF),
            None => Ok(INVALID_INPUTS),
        }
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_codes() {
        assert_eq!(SUCCESS, 0);
        assert_eq!(INVALID_PROOF, 1);
        assert_eq!(INVALID_INPUTS, 2);
    }
}
