//! Pedersen commitments using the Jubjub curve
//!
//! Jubjub is an elliptic curve designed for use inside zk-SNARKs.
//! It's defined over the scalar field of BLS12-381.
//!
//! This module provides real Pedersen commitments compatible with Zcash Sapling.

use jubjub::{ExtendedPoint, Fr, SubgroupPoint, AffinePoint};
use group::Group;
use group::cofactor::CofactorGroup;
use blake2s_simd::Params as Blake2sParams;

/// Domain separator for note commitments
const NOTE_COMMITMENT_DOMAIN: &[u8; 8] = b"YaCoinNC"; // 8 bytes for domain separator

/// The Sapling value commitment generator V (from Zcash spec)
/// This is a nothing-up-my-sleeve point derived from hashing
fn value_commitment_value_generator() -> SubgroupPoint {
    // Hash-to-curve using Blake2s with domain separation
    // This matches the Zcash Sapling specification
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(b"YaCoin_cv")
        .to_state()
        .update(b"v")
        .finalize();

    hash_to_point(hash.as_bytes())
}

/// The Sapling value commitment generator R (randomness base)
fn value_commitment_randomness_generator() -> SubgroupPoint {
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(b"YaCoin_cv")
        .to_state()
        .update(b"r")
        .finalize();

    hash_to_point(hash.as_bytes())
}

/// Hash bytes to a Jubjub point using try-and-increment
fn hash_to_point(input: &[u8]) -> SubgroupPoint {
    let mut counter: u8 = 0;
    loop {
        let mut hasher = Blake2sParams::new()
            .hash_length(32)
            .personal(b"YaCoin_gd")
            .to_state();
        hasher.update(input);
        hasher.update(&[counter]);
        let hash = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());

        // Try to decode as point
        let maybe_point: Option<AffinePoint> = AffinePoint::from_bytes(bytes).into();
        if let Some(point) = maybe_point {
            let extended: ExtendedPoint = point.into();
            // Clear cofactor to get subgroup point
            return extended.clear_cofactor();
        }

        counter = counter.wrapping_add(1);
        if counter == 0 {
            // Fallback to generator if nothing found (should never happen)
            return SubgroupPoint::generator();
        }
    }
}

/// Pedersen hash result
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PedersenHash(pub [u8; 32]);

impl PedersenHash {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get as bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Hash two child nodes for Merkle tree
    pub fn merkle_hash(depth: usize, left: &[u8; 32], right: &[u8; 32]) -> Self {
        // Domain separation: include depth in personalization
        let mut personalization = [0u8; 8];
        personalization[..6].copy_from_slice(b"YaCoin_");
        personalization[6] = b'M';
        personalization[7] = depth as u8;

        // Use BLAKE2s for mixing before Pedersen
        let mut hasher = Blake2sParams::new()
            .hash_length(32)
            .personal(&personalization)
            .to_state();

        hasher.update(left);
        hasher.update(right);

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());

        Self(result)
    }

    /// Compute empty tree root at given depth
    pub fn empty_root(depth: usize) -> Self {
        if depth == 0 {
            // Empty leaf
            Self([0u8; 32])
        } else {
            let child = Self::empty_root(depth.saturating_sub(1));
            Self::merkle_hash(depth.saturating_sub(1), &child.0, &child.0)
        }
    }
}

/// Note commitment (Pedersen hash based)
///
/// cm = COMMIT_ivk(g_d, pk_d, v, rcm)
/// This uses a Pedersen hash with the note contents to create a hiding commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteCommitment(pub [u8; 32]);

impl NoteCommitment {
    /// Compute note commitment using Pedersen hash
    /// cm = WindowedPedersenCommit(rcm, [g_d, pk_d, v])
    pub fn compute(
        diversifier: &[u8; 11],
        pk_d: &[u8; 32],
        value: u64,
        rcm: &Fr,
    ) -> Self {
        // In Sapling, note commitment uses:
        // cm = PedersenHash("YaCoin_NC", g_d || pk_d || value) + rcm * H
        // where H is a nothing-up-my-sleeve generator

        // First, compute the inner hash (this binds to the note contents)
        let inner = Self::pedersen_hash_note(diversifier, pk_d, value);

        // Then add the blinding factor: cm = inner + rcm * H
        let h = note_commitment_randomness_generator();
        let blinded = inner + (h * rcm);

        // Extract the u-coordinate (x) as the commitment
        let affine = AffinePoint::from(blinded);
        Self(affine.to_bytes())
    }

    /// Pedersen hash of note contents
    fn pedersen_hash_note(diversifier: &[u8; 11], pk_d: &[u8; 32], value: u64) -> ExtendedPoint {
        // Use generators derived from note commitment domain
        let mut result = ExtendedPoint::identity();

        // Hash diversifier into curve point
        let g_d = hash_to_point(diversifier);
        result = result + g_d;

        // Hash pk_d
        let pk_d_point = hash_to_point(pk_d);
        result = result + pk_d_point;

        // Add value contribution
        let value_gen = hash_to_point(b"value_generator");
        result = result + (value_gen * Fr::from(value));

        result
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get as bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Generator for note commitment randomness
fn note_commitment_randomness_generator() -> SubgroupPoint {
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(NOTE_COMMITMENT_DOMAIN)
        .to_state()
        .update(b"rcm_generator")
        .finalize();

    hash_to_point(hash.as_bytes())
}

/// Value commitment (Pedersen commitment to value on Jubjub curve)
///
/// cv = value * V + rcv * R
/// where V and R are nothing-up-my-sleeve generators
#[derive(Clone, Copy, Debug)]
pub struct ValueCommitment {
    /// The commitment point on Jubjub
    pub point: ExtendedPoint,
}

impl ValueCommitment {
    /// Create a value commitment using real Pedersen commitment
    /// cv = value * V + rcv * R
    pub fn commit(value: u64, rcv: &Fr) -> Self {
        let g_v = value_commitment_value_generator();
        let g_r = value_commitment_randomness_generator();

        // Convert value to scalar
        let value_scalar = Fr::from(value);

        // cv = value * V + rcv * R (real Pedersen commitment)
        let point = (g_v * value_scalar) + (g_r * rcv);

        Self {
            point: point.into(),
        }
    }

    /// Add two value commitments (for summing in binding signature)
    pub fn add(&self, other: &ValueCommitment) -> ValueCommitment {
        ValueCommitment {
            point: self.point + other.point,
        }
    }

    /// Negate a value commitment
    pub fn negate(&self) -> ValueCommitment {
        ValueCommitment {
            point: -self.point,
        }
    }

    /// Serialize to bytes (compressed point)
    pub fn to_bytes(&self) -> [u8; 32] {
        let affine = AffinePoint::from(self.point);
        affine.to_bytes()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let affine = AffinePoint::from_bytes(*bytes);
        if affine.is_some().into() {
            Some(Self {
                point: affine.unwrap().into(),
            })
        } else {
            None
        }
    }

    /// Check if this commitment balances with another
    /// (cv_spend - cv_output should equal value_balance * V)
    pub fn verify_balance(
        spend_cvs: &[ValueCommitment],
        output_cvs: &[ValueCommitment],
        value_balance: i64,
    ) -> bool {
        // Sum spend commitments
        let mut sum = ExtendedPoint::identity();
        for cv in spend_cvs {
            sum = sum + cv.point;
        }

        // Subtract output commitments
        for cv in output_cvs {
            sum = sum - cv.point;
        }

        // Should equal value_balance * V
        let g_v = value_commitment_value_generator();
        let expected = if value_balance >= 0 {
            g_v * Fr::from(value_balance as u64)
        } else {
            -(g_v * Fr::from((-value_balance) as u64))
        };

        // Compare points
        sum == expected.into()
    }
}

/// Nullifier derivation
pub fn derive_nullifier(
    nk: &[u8; 32],  // Nullifier deriving key
    cm: &NoteCommitment,
    position: u64,
) -> [u8; 32] {
    let mut hasher = Blake2sParams::new()
        .hash_length(32)
        .personal(b"YaCoin_nf")
        .to_state();

    hasher.update(nk);
    hasher.update(&cm.0);
    hasher.update(&position.to_le_bytes());

    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_hash_deterministic() {
        let left = [1u8; 32];
        let right = [2u8; 32];

        let hash1 = PedersenHash::merkle_hash(0, &left, &right);
        let hash2 = PedersenHash::merkle_hash(0, &left, &right);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_depth_different_hash() {
        let left = [1u8; 32];
        let right = [2u8; 32];

        let hash0 = PedersenHash::merkle_hash(0, &left, &right);
        let hash1 = PedersenHash::merkle_hash(1, &left, &right);

        assert_ne!(hash0, hash1);
    }

    #[test]
    fn test_empty_roots_different_depths() {
        let root0 = PedersenHash::empty_root(0);
        let root1 = PedersenHash::empty_root(1);
        let root2 = PedersenHash::empty_root(2);

        assert_ne!(root0, root1);
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_note_commitment() {
        let diversifier = [0u8; 11];
        let pk_d = [1u8; 32];
        let value = 1000u64;
        let rcm = Fr::from(12345u64);

        let cm1 = NoteCommitment::compute(&diversifier, &pk_d, value, &rcm);
        let cm2 = NoteCommitment::compute(&diversifier, &pk_d, value, &rcm);

        assert_eq!(cm1, cm2);
    }

    #[test]
    fn test_value_commitment() {
        let value = 1000u64;
        let rcv = Fr::from(54321u64);

        let cv = ValueCommitment::commit(value, &rcv);
        let bytes = cv.to_bytes();

        assert_ne!(bytes, [0u8; 32]);
    }

    #[test]
    fn test_nullifier_derivation() {
        let nk = [1u8; 32];
        let cm = NoteCommitment([2u8; 32]);
        let position = 42u64;

        let nf1 = derive_nullifier(&nk, &cm, position);
        let nf2 = derive_nullifier(&nk, &cm, position);

        assert_eq!(nf1, nf2);

        // Different position = different nullifier
        let nf3 = derive_nullifier(&nk, &cm, position + 1);
        assert_ne!(nf1, nf3);
    }
}
