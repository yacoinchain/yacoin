//! Real Groth16 proof generation using Sapling circuits
//!
//! This module generates actual zk-SNARK proofs using:
//! - The sapling-crypto crate's circuit implementations
//! - Sapling parameters (spend/output proving keys)
//! - Bellman's Groth16 proving system
//!
//! These are real, verifiable proofs - not placeholders.

use jubjub::Fr;
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, Bytes};
use std::path::PathBuf;

use crate::keys::SpendingKey;
use crate::note::Note;
use crate::commitment::NoteCommitment;  // Only for MerkleWitness::root()
use crate::error::WalletError;
use crate::GROTH_PROOF_SIZE;

#[cfg(feature = "prover")]
use rand_core::OsRng;

// Import the real Sapling circuit types
#[cfg(feature = "prover")]
use sapling_crypto::{
    circuit::{SpendParameters, OutputParameters},
    Diversifier as SaplingDiversifier,
    PaymentAddress as SaplingPaymentAddress,
    Note as SaplingNote,
    Rseed,
    Node,
    keys::ExpandedSpendingKey,
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment as SaplingValueCommitment},
    prover::{SpendProver, OutputProver},
};

/// Spend proof - proves ownership of a note without revealing it
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendProof {
    /// The Groth16 proof (192 bytes)
    #[serde_as(as = "Bytes")]
    pub proof: [u8; GROTH_PROOF_SIZE],
    /// Value commitment
    pub cv: [u8; 32],
    /// Merkle root anchor
    pub anchor: [u8; 32],
    /// Nullifier (unique identifier for this spend)
    pub nullifier: [u8; 32],
    /// Randomized verification key
    pub rk: [u8; 32],
}

/// Output proof - proves valid creation of a new note
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputProof {
    /// The Groth16 proof (192 bytes)
    #[serde_as(as = "Bytes")]
    pub proof: [u8; GROTH_PROOF_SIZE],
    /// Value commitment
    pub cv: [u8; 32],
    /// Note commitment
    pub cmu: [u8; 32],
    /// Ephemeral public key
    pub epk: [u8; 32],
}

/// Merkle witness for proving note inclusion
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleWitness {
    /// Path of sibling hashes (32 levels)
    #[serde_as(as = "[_; 32]")]
    pub path: [[u8; 32]; 32],
    /// Position bits (0 = left, 1 = right)
    pub position: u64,
}

impl MerkleWitness {
    /// Compute the root from a leaf commitment
    pub fn root(&self, leaf: &NoteCommitment) -> [u8; 32] {
        use crate::commitment::merkle_hash;

        let mut current = leaf.0;

        for depth in 0..32 {
            let is_right = (self.position >> depth) & 1 == 1;

            current = if is_right {
                merkle_hash(depth, &self.path[depth], &current)
            } else {
                merkle_hash(depth, &current, &self.path[depth])
            };
        }

        current
    }

    /// Convert to Sapling MerklePath format
    #[cfg(feature = "prover")]
    pub fn to_sapling_path(&self) -> sapling_crypto::MerklePath {
        use incrementalmerkletree::Position;

        // Convert our witness format to Sapling's MerklePath
        // MerklePath::from_parts expects Vec<Node> where Node wraps bls12_381::Scalar
        let auth_path: Vec<Node> = self.path.iter().filter_map(|h| {
            Node::from_bytes(*h).into()
        }).collect();

        let position = Position::from(self.position);

        sapling_crypto::MerklePath::from_parts(auth_path, position).expect("valid merkle path")
    }
}

/// Main prover for shielded transactions
pub struct ShieldedProver {
    /// Path to Sapling parameters
    params_dir: PathBuf,
    /// Cached spend parameters
    #[cfg(feature = "prover")]
    spend_params: Option<SpendParameters>,
    /// Cached output parameters
    #[cfg(feature = "prover")]
    output_params: Option<OutputParameters>,
}

impl ShieldedProver {
    /// Create a new prover with default parameter location
    pub fn new() -> Result<Self, WalletError> {
        let params_dir = get_params_dir();
        Self::with_params_dir(params_dir)
    }

    /// Create prover with specific parameter directory
    pub fn with_params_dir(params_dir: PathBuf) -> Result<Self, WalletError> {
        Ok(Self {
            params_dir,
            #[cfg(feature = "prover")]
            spend_params: None,
            #[cfg(feature = "prover")]
            output_params: None,
        })
    }

    /// Check if Sapling parameters are available
    pub fn params_available(&self) -> bool {
        let spend_path = self.params_dir.join("sapling-spend.params");
        let output_path = self.params_dir.join("sapling-output.params");
        spend_path.exists() && output_path.exists()
    }

    /// Get the parameters directory
    pub fn params_dir(&self) -> &PathBuf {
        &self.params_dir
    }

    /// Load Sapling parameters
    #[cfg(feature = "prover")]
    pub fn load_params(&mut self) -> Result<(), WalletError> {
        self.ensure_spend_params()?;
        self.ensure_output_params()?;
        Ok(())
    }

    /// Generate a spend proof using the real Sapling circuit
    #[cfg(feature = "prover")]
    pub fn create_spend_proof(
        &mut self,
        sk: &SpendingKey,
        note: &Note,
        witness: &MerkleWitness,
        anchor: [u8; 32],
        rcv: Fr,
    ) -> Result<SpendProof, WalletError> {
        use rand_core::RngCore;

        // Load parameters if needed
        self.ensure_spend_params()?;
        let params = self.spend_params.as_ref().unwrap();

        // Get the spending key bytes and derive keys using sapling_crypto's API
        let sk_bytes = sk.to_bytes();
        let expsk = ExpandedSpendingKey::from_spending_key(&sk_bytes);
        let proof_generation_key = expsk.proof_generation_key();

        // Convert our types to Sapling types
        let diversifier = SaplingDiversifier(note.diversifier);

        // Rseed from note
        let rseed = Rseed::AfterZip212(note.rseed);

        // Note value
        let value = NoteValue::from_raw(note.value);

        // Value commitment trapdoor - convert our Fr to sapling's ValueCommitTrapdoor
        let rcv_trapdoor = ValueCommitTrapdoor::from_bytes(rcv.to_bytes())
            .into_option()
            .ok_or(WalletError::InvalidNote)?;

        // Anchor as scalar
        let anchor_scalar = bls12_381::Scalar::from_bytes(&anchor)
            .unwrap_or(bls12_381::Scalar::zero());

        // Merkle path
        let merkle_path = witness.to_sapling_path();

        // Generate randomness for proof (alpha for rk randomization)
        let mut alpha_bytes = [0u8; 64];
        OsRng.fill_bytes(&mut alpha_bytes);
        let alpha = Fr::from_bytes_wide(&alpha_bytes);

        // Prepare the circuit (clone rcv_trapdoor so we can use it later for cv)
        let circuit = SpendParameters::prepare_circuit(
            proof_generation_key.clone(),
            diversifier,
            rseed,
            value,
            alpha,
            rcv_trapdoor.clone(),
            anchor_scalar,
            merkle_path,
        ).ok_or(WalletError::InvalidNote)?;

        // Create the proof
        let proof = params.create_proof(circuit, &mut OsRng);

        // Encode proof to bytes
        let proof_bytes = SpendParameters::encode_proof(proof);

        // ============================================================
        // USE REAL SAPLING COMMITMENTS - NOT OUR CUSTOM BROKEN CODE
        // ============================================================

        // Create real Sapling note to get correct commitment and nullifier
        // Build payment address
        let mut addr_bytes = [0u8; 43];
        addr_bytes[0..11].copy_from_slice(&note.diversifier);
        addr_bytes[11..43].copy_from_slice(&note.pk_d);
        let payment_address = SaplingPaymentAddress::from_bytes(&addr_bytes)
            .ok_or(WalletError::InvalidPaymentAddress)?;

        let sapling_note = SaplingNote::from_parts(payment_address, value, rseed);

        // Compute REAL value commitment using Sapling's ValueCommitment
        // Note: derive(value, rcv) not derive(rcv, value)
        let cv = SaplingValueCommitment::derive(value, rcv_trapdoor);
        let cv_bytes = cv.to_bytes();

        // Get the viewing key to access nk (nullifier deriving key)
        let vk = proof_generation_key.to_viewing_key();

        // Get REAL nullifier from Sapling note
        // nf = PRF_nk(rho) where rho is derived from the note position
        let nf = sapling_note.nf(&vk.nk, witness.position);
        let nullifier_bytes = nf.0;
        let rk = vk.rk(alpha);
        let rk_bytes: [u8; 32] = rk.into();

        Ok(SpendProof {
            proof: proof_bytes,
            cv: cv_bytes,
            anchor,
            nullifier: nullifier_bytes,
            rk: rk_bytes,
        })
    }

    /// Generate an output proof using the real Sapling circuit
    #[cfg(feature = "prover")]
    pub fn create_output_proof(
        &mut self,
        note: &Note,
        rcv: Fr,
    ) -> Result<OutputProof, WalletError> {

        // Load parameters if needed
        self.ensure_output_params()?;
        let params = self.output_params.as_ref().unwrap();

        // Convert our types to Sapling types
        let diversifier = SaplingDiversifier(note.diversifier);

        // Build 43-byte payment address: diversifier (11) + pk_d (32)
        let mut addr_bytes = [0u8; 43];
        addr_bytes[0..11].copy_from_slice(&note.diversifier);
        addr_bytes[11..43].copy_from_slice(&note.pk_d);

        // Create payment address from bytes
        let payment_address = SaplingPaymentAddress::from_bytes(&addr_bytes)
            .ok_or(WalletError::InvalidPaymentAddress)?;

        // Value commitment trapdoor - convert our Fr to sapling's ValueCommitTrapdoor
        let rcv_trapdoor = ValueCommitTrapdoor::from_bytes(rcv.to_bytes())
            .into_option()
            .ok_or(WalletError::InvalidNote)?;

        // Note value
        let value = NoteValue::from_raw(note.value);

        // Create a sapling Note to derive esk from rseed
        let rseed = Rseed::AfterZip212(note.rseed);
        let sapling_note = SaplingNote::from_parts(payment_address, value, rseed);

        // Derive esk from the note (uses rseed for deterministic derivation)
        let esk = sapling_note.generate_or_derive_esk(&mut OsRng);

        // rcm (note commitment randomness) - derive from rseed same way Sapling does
        let rcm = sapling_note.rcm();

        // Prepare the circuit (clone rcv_trapdoor so we can use it later for cv)
        let circuit = OutputParameters::prepare_circuit(
            &esk,
            payment_address,
            rcm,
            value,
            rcv_trapdoor.clone(),
        );

        // Create the proof
        let proof = params.create_proof(circuit, &mut OsRng);

        // Encode proof to bytes
        let proof_bytes = OutputParameters::encode_proof(proof);

        // ============================================================
        // USE REAL SAPLING COMMITMENTS - NOT OUR CUSTOM BROKEN CODE
        // ============================================================

        // Get the REAL note commitment from sapling_note (what the circuit proves)
        let cmu_scalar = sapling_note.cmu();
        let cmu_bytes = cmu_scalar.to_bytes();

        // Compute REAL value commitment using Sapling's ValueCommitment
        // Note: derive(value, rcv) not derive(rcv, value)
        let cv = SaplingValueCommitment::derive(value, rcv_trapdoor);
        let cv_bytes = cv.to_bytes();

        // Compute ephemeral public key using Sapling's diversifier
        let g_d = diversifier.g_d()
            .ok_or(WalletError::InvalidDiversifier)?;

        // Derive esk from rseed using Sapling's PRF (same as circuit uses)
        let esk_scalar = jubjub::Fr::from_bytes_wide(
            &zcash_spec::PrfExpand::SAPLING_ESK.with(&note.rseed)
        );
        let epk_point: jubjub::ExtendedPoint = (g_d * esk_scalar).into();
        let epk_bytes = jubjub::AffinePoint::from(epk_point).to_bytes();

        Ok(OutputProof {
            proof: proof_bytes,
            cv: cv_bytes,
            cmu: cmu_bytes,
            epk: epk_bytes,
        })
    }

    /// Load spend parameters from file
    #[cfg(feature = "prover")]
    fn ensure_spend_params(&mut self) -> Result<(), WalletError> {
        if self.spend_params.is_some() {
            return Ok(());
        }

        let path = self.params_dir.join("sapling-spend.params");
        if !path.exists() {
            return Err(WalletError::ParamsNotFound);
        }

        let file = std::fs::File::open(&path)?;
        let mut reader = std::io::BufReader::new(file);

        let params = SpendParameters::read(&mut reader, false)
            .map_err(|e| WalletError::ProofGenerationFailed(format!("Failed to load spend params: {:?}", e)))?;

        self.spend_params = Some(params);
        Ok(())
    }

    /// Load output parameters from file
    #[cfg(feature = "prover")]
    fn ensure_output_params(&mut self) -> Result<(), WalletError> {
        if self.output_params.is_some() {
            return Ok(());
        }

        let path = self.params_dir.join("sapling-output.params");
        if !path.exists() {
            return Err(WalletError::ParamsNotFound);
        }

        let file = std::fs::File::open(&path)?;
        let mut reader = std::io::BufReader::new(file);

        let params = OutputParameters::read(&mut reader, false)
            .map_err(|e| WalletError::ProofGenerationFailed(format!("Failed to load output params: {:?}", e)))?;

        self.output_params = Some(params);
        Ok(())
    }

    // Non-prover feature stubs
    #[cfg(not(feature = "prover"))]
    pub fn create_spend_proof(
        &mut self,
        _sk: &SpendingKey,
        _note: &Note,
        _witness: &MerkleWitness,
        _anchor: [u8; 32],
        _rcv: Fr,
    ) -> Result<SpendProof, WalletError> {
        Err(WalletError::ProofGenerationFailed(
            "Prover feature not enabled. Rebuild with --features prover".to_string()
        ))
    }

    #[cfg(not(feature = "prover"))]
    pub fn create_output_proof(
        &mut self,
        _note: &Note,
        _rcv: Fr,
    ) -> Result<OutputProof, WalletError> {
        Err(WalletError::ProofGenerationFailed(
            "Prover feature not enabled. Rebuild with --features prover".to_string()
        ))
    }
}

impl Default for ShieldedProver {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            params_dir: get_params_dir(),
            #[cfg(feature = "prover")]
            spend_params: None,
            #[cfg(feature = "prover")]
            output_params: None,
        })
    }
}

/// Get the default parameters directory
pub fn get_params_dir() -> PathBuf {
    // Check environment variable first
    if let Ok(dir) = std::env::var("YACOIN_PARAMS") {
        return PathBuf::from(dir);
    }

    // Check ~/.yacoin/params/
    if let Some(home) = dirs::home_dir() {
        let yacoin_params = home.join(".yacoin").join("params");
        if yacoin_params.exists() {
            return yacoin_params;
        }

        // Also check ~/.zcash-params/ for compatibility
        let zcash_params = home.join(".zcash-params");
        if zcash_params.exists() {
            return zcash_params;
        }

        // Return default YaCoin location even if it doesn't exist yet
        return yacoin_params;
    }

    // Fallback to current directory
    PathBuf::from("params")
}

/// Download Sapling parameters (stub - actual download happens externally)
pub fn download_params() -> Result<PathBuf, WalletError> {
    let dir = get_params_dir();

    // Create directory if needed
    std::fs::create_dir_all(&dir)?;

    // Check if params already exist
    let spend_path = dir.join("sapling-spend.params");
    let output_path = dir.join("sapling-output.params");

    if spend_path.exists() && output_path.exists() {
        return Ok(dir);
    }

    // Return instructions for downloading
    Err(WalletError::ProofGenerationFailed(format!(
        "Sapling parameters not found at {:?}\n\
         Download them with:\n\
         wget https://download.z.cash/downloads/sapling-spend.params -O {:?}\n\
         wget https://download.z.cash/downloads/sapling-output.params -O {:?}",
        dir,
        spend_path,
        output_path
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params_dir() {
        let dir = get_params_dir();
        assert!(dir.to_string_lossy().len() > 0);
    }

    #[test]
    fn test_merkle_witness() {
        let leaf = NoteCommitment([1u8; 32]);
        let witness = MerkleWitness {
            path: [[2u8; 32]; 32],
            position: 0,
        };

        let root = witness.root(&leaf);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_prover_creation() {
        let prover = ShieldedProver::new();
        assert!(prover.is_ok());
    }
}
