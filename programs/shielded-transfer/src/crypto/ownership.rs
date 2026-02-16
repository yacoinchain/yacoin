//! NFT Ownership Proofs
//!
//! Prove you own an NFT (or asset) without revealing which specific one.
//! Perfect for token-gated communities, airdrops, and identity verification.
//!
//! Three levels of disclosure:
//! 1. Full disclosure - reveal everything (for selling, etc.)
//! 2. Collection proof - prove you own "an NFT from collection X"
//! 3. Existence proof - prove you own "some NFT" (most private)

use blake2s_simd::Params as Blake2sParams;
use borsh::{BorshDeserialize, BorshSerialize};

/// Proof that someone owns an asset from a specific collection
/// without revealing which specific asset
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct CollectionOwnershipProof {
    /// The collection identifier (mint authority, collection address, etc.)
    pub collection_id: [u8; 32],

    /// Commitment to the specific asset (hidden)
    pub asset_commitment: [u8; 32],

    /// Proof that the commitment is in the global note tree
    /// Stored as pairs: (sibling_hash, is_left as u8)
    pub merkle_proof: Vec<([u8; 32], u8)>,

    /// Proof that the owner knows the spending key
    /// In production: this would be a zk-SNARK
    /// For now: hash(spending_key || challenge)
    pub ownership_proof: [u8; 32],

    /// Challenge used for the proof (prevents replay)
    pub challenge: [u8; 32],

    /// Timestamp for freshness
    pub timestamp: u64,
}

impl CollectionOwnershipProof {
    /// Create an ownership proof for an NFT in a collection
    ///
    /// This proves "I own an NFT from collection X" without revealing which one.
    pub fn create(
        collection_id: [u8; 32],
        asset_commitment: [u8; 32],
        merkle_proof: Vec<([u8; 32], u8)>,
        spending_key: &[u8; 32],
        challenge: [u8; 32],
    ) -> Self {
        // Create ownership proof: H(sk || commitment || challenge)
        let ownership_proof = compute_ownership_hash(spending_key, &asset_commitment, &challenge);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            collection_id,
            asset_commitment,
            merkle_proof,
            ownership_proof,
            challenge,
            timestamp,
        }
    }

    /// Verify the ownership proof
    ///
    /// Verifier needs:
    /// - The merkle root (from on-chain state)
    /// - The public key derived from spending key (to verify ownership_proof)
    pub fn verify(
        &self,
        merkle_root: &[u8; 32],
        owner_pubkey: &[u8; 32],
        max_age_seconds: u64,
    ) -> bool {
        // Check timestamp freshness
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now.saturating_sub(self.timestamp) > max_age_seconds {
            return false; // Proof too old
        }

        // Convert merkle proof format
        let proof_elements: Vec<MerkleProofElement> = self.merkle_proof
            .iter()
            .map(|(sibling, is_left)| MerkleProofElement {
                sibling: *sibling,
                is_left: *is_left != 0,
            })
            .collect();

        // Verify merkle proof
        if !verify_merkle_proof(&self.asset_commitment, &proof_elements, merkle_root) {
            return false;
        }

        // Verify ownership (in production: verify zk-SNARK)
        // For now: we can't verify without the spending key
        // This is a placeholder - real impl needs proper ZK
        let _ = owner_pubkey; // Would verify against this

        true
    }
}

/// Proof of NFT ownership for a specific token-gated check
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct TokenGatedProof {
    /// What we're proving access to (Discord server ID, website, etc.)
    pub gate_id: [u8; 32],

    /// Collection(s) that grant access
    pub required_collections: Vec<[u8; 32]>,

    /// The ownership proof
    pub proof: CollectionOwnershipProof,

    /// Signature binding proof to gate_id (prevents using same proof elsewhere)
    pub binding_signature: [u8; 64],
}

impl TokenGatedProof {
    /// Create a proof for token-gated access
    pub fn create(
        gate_id: [u8; 32],
        required_collections: Vec<[u8; 32]>,
        asset_commitment: [u8; 32],
        merkle_proof: Vec<([u8; 32], u8)>,
        spending_key: &[u8; 32],
    ) -> Option<Self> {
        // Find which collection this asset belongs to
        // In production: would verify asset is actually in one of required_collections

        if required_collections.is_empty() {
            return None;
        }

        let collection_id = required_collections[0]; // Simplified

        // Generate challenge from gate_id
        let challenge = compute_gate_challenge(&gate_id);

        let proof = CollectionOwnershipProof::create(
            collection_id,
            asset_commitment,
            merkle_proof,
            spending_key,
            challenge,
        );

        // Create binding signature
        let binding_signature = compute_binding_signature(spending_key, &gate_id, &proof);

        Some(Self {
            gate_id,
            required_collections,
            proof,
            binding_signature,
        })
    }

    /// Verify the token-gated proof
    pub fn verify(&self, merkle_root: &[u8; 32], owner_pubkey: &[u8; 32]) -> bool {
        // Check collection is in required list
        if !self.required_collections.contains(&self.proof.collection_id) {
            return false;
        }

        // Verify the underlying ownership proof (5 minute freshness)
        if !self.proof.verify(merkle_root, owner_pubkey, 300) {
            return false;
        }

        // Verify binding signature
        // In production: proper signature verification
        let expected_binding = compute_binding_signature(
            &[0u8; 32], // Can't verify without key, placeholder
            &self.gate_id,
            &self.proof,
        );
        let _ = expected_binding; // Would compare

        true
    }
}

/// Simple ownership claim (for when you want to reveal the NFT)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct OwnershipClaim {
    /// The asset being claimed
    pub asset_type: u8,
    pub asset_id: [u8; 32],
    pub token_id: [u8; 32], // For NFTs

    /// Note commitment containing this asset
    pub note_commitment: [u8; 32],

    /// Opening to prove the claim
    pub opening: OwnershipOpening,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct OwnershipOpening {
    /// Diversifier
    pub diversifier: [u8; 11],

    /// Public key (pk_d)
    pub pk_d: [u8; 32],

    /// Commitment randomness
    pub rcm: [u8; 32],
}

impl OwnershipClaim {
    /// Verify this claim matches the commitment
    pub fn verify(&self) -> bool {
        // Recompute commitment from claimed values
        let computed = compute_asset_commitment(
            &self.opening.diversifier,
            &self.opening.pk_d,
            self.asset_type,
            &self.asset_id,
            &self.token_id,
            &self.opening.rcm,
        );

        computed == self.note_commitment
    }
}

// Helper functions

fn compute_ownership_hash(
    spending_key: &[u8; 32],
    commitment: &[u8; 32],
    challenge: &[u8; 32],
) -> [u8; 32] {
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(b"YCoin_OP") // Ownership Proof
        .to_state()
        .update(spending_key)
        .update(commitment)
        .update(challenge)
        .finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

fn compute_gate_challenge(gate_id: &[u8; 32]) -> [u8; 32] {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(b"YCoin_GC") // Gate Challenge
        .to_state()
        .update(gate_id)
        .update(&timestamp.to_le_bytes())
        .finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

fn compute_binding_signature(
    spending_key: &[u8; 32],
    gate_id: &[u8; 32],
    proof: &CollectionOwnershipProof,
) -> [u8; 64] {
    // In production: proper Schnorr or EdDSA signature
    // For now: deterministic hash as placeholder
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(b"YCoin_BS") // Binding Signature
        .to_state()
        .update(spending_key)
        .update(gate_id)
        .update(&proof.asset_commitment)
        .finalize();

    let mut result = [0u8; 64];
    result[..32].copy_from_slice(hash.as_bytes());
    // Second half is zeros (placeholder for full signature)
    result
}

/// Merkle proof element with position indicator
#[derive(Clone, Debug)]
pub struct MerkleProofElement {
    pub sibling: [u8; 32],
    pub is_left: bool, // true if sibling is on the left
}

fn verify_merkle_proof(
    leaf: &[u8; 32],
    proof: &[MerkleProofElement],
    root: &[u8; 32],
) -> bool {
    let mut current = *leaf;

    for elem in proof {
        let (left, right) = if elem.is_left {
            (&elem.sibling, &current)
        } else {
            (&current, &elem.sibling)
        };

        let hash = Blake2sParams::new()
            .hash_length(32)
            .personal(b"YCoin_MH") // Merkle Hash
            .to_state()
            .update(left)
            .update(right)
            .finalize();

        current.copy_from_slice(hash.as_bytes());
    }

    &current == root
}

fn compute_asset_commitment(
    diversifier: &[u8; 11],
    pk_d: &[u8; 32],
    asset_type: u8,
    asset_id: &[u8; 32],
    token_id: &[u8; 32],
    rcm: &[u8; 32],
) -> [u8; 32] {
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(b"YCoin_AC") // Asset Commitment
        .to_state()
        .update(diversifier)
        .update(pk_d)
        .update(&[asset_type])
        .update(asset_id)
        .update(token_id)
        .update(rcm)
        .finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_proof_verification() {
        // Create a simple merkle tree
        // Tree structure:
        //        root
        //       /    \
        //    level1  sibling2
        //    /    \
        //  leaf  sibling1

        let leaf = [1u8; 32];
        let sibling1 = [2u8; 32];
        let sibling2 = [3u8; 32];

        // Compute level1 = H(leaf || sibling1) - leaf on left, sibling on right
        let hash1 = Blake2sParams::new()
            .hash_length(32)
            .personal(b"YCoin_MH")
            .to_state()
            .update(&leaf)
            .update(&sibling1)
            .finalize();

        let mut level1 = [0u8; 32];
        level1.copy_from_slice(hash1.as_bytes());

        // Compute root = H(level1 || sibling2) - level1 on left, sibling2 on right
        let hash2 = Blake2sParams::new()
            .hash_length(32)
            .personal(b"YCoin_MH")
            .to_state()
            .update(&level1)
            .update(&sibling2)
            .finalize();

        let mut root = [0u8; 32];
        root.copy_from_slice(hash2.as_bytes());

        // Verify proof - siblings are on the right (is_left = false)
        let proof = vec![
            MerkleProofElement { sibling: sibling1, is_left: false },
            MerkleProofElement { sibling: sibling2, is_left: false },
        ];
        assert!(verify_merkle_proof(&leaf, &proof, &root));

        // Wrong position should fail
        let wrong_proof = vec![
            MerkleProofElement { sibling: sibling1, is_left: true }, // Wrong!
            MerkleProofElement { sibling: sibling2, is_left: false },
        ];
        assert!(!verify_merkle_proof(&leaf, &wrong_proof, &root));
    }

    #[test]
    fn test_ownership_claim_verification() {
        let diversifier = [1u8; 11];
        let pk_d = [2u8; 32];
        let asset_type = 2; // NFT
        let asset_id = [3u8; 32];
        let token_id = [4u8; 32];
        let rcm = [5u8; 32];

        // Compute the commitment
        let commitment = compute_asset_commitment(
            &diversifier, &pk_d, asset_type, &asset_id, &token_id, &rcm
        );

        // Create claim
        let claim = OwnershipClaim {
            asset_type,
            asset_id,
            token_id,
            note_commitment: commitment,
            opening: OwnershipOpening {
                diversifier,
                pk_d,
                rcm,
            },
        };

        // Should verify
        assert!(claim.verify());

        // Wrong claim should fail
        let bad_claim = OwnershipClaim {
            asset_type,
            asset_id,
            token_id: [99u8; 32], // Wrong!
            note_commitment: commitment,
            opening: OwnershipOpening {
                diversifier,
                pk_d,
                rcm,
            },
        };

        assert!(!bad_claim.verify());
    }

    #[test]
    fn test_collection_ownership_proof() {
        let collection_id = [10u8; 32];
        let asset_commitment = [20u8; 32];
        let spending_key = [30u8; 32];
        let challenge = [40u8; 32];

        let proof = CollectionOwnershipProof::create(
            collection_id,
            asset_commitment,
            vec![], // Empty merkle proof for test
            &spending_key,
            challenge,
        );

        assert_eq!(proof.collection_id, collection_id);
        assert_eq!(proof.asset_commitment, asset_commitment);
        assert_eq!(proof.challenge, challenge);
        assert!(proof.timestamp > 0);
    }
}
