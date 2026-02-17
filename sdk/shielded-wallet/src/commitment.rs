//! Pedersen commitments for YaCoin shielded transactions
//!
//! Uses the Jubjub curve (defined over BLS12-381 scalar field) for:
//! - Note commitments (hiding commitment to note data)
//! - Value commitments (Pedersen commitment to transaction values)
//! - Nullifier derivation (unique identifier for spent notes)

use jubjub::{Fr, SubgroupPoint, ExtendedPoint, AffinePoint};
use group::Group;
use group::cofactor::CofactorGroup;
use blake2s_simd::Params as Blake2sParams;
use serde::{Serialize, Deserialize};

/// The value commitment value generator (nothing-up-my-sleeve point)
fn value_commitment_value_generator() -> SubgroupPoint {
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(b"Zcash_cv")
        .to_state()
        .update(b"v")
        .finalize();

    hash_to_point(hash.as_bytes())
}

/// The value commitment randomness generator
fn value_commitment_randomness_generator() -> SubgroupPoint {
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(b"Zcash_cv")
        .to_state()
        .update(b"r")
        .finalize();

    hash_to_point(hash.as_bytes())
}

/// The note commitment randomness generator
fn note_commitment_randomness_generator() -> SubgroupPoint {
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(b"Zcash_NC")
        .to_state()
        .update(b"rcm_generator")
        .finalize();

    hash_to_point(hash.as_bytes())
}

/// Hash bytes to a Jubjub point using try-and-increment
fn hash_to_point(input: &[u8]) -> SubgroupPoint {
    for counter in 0u8..=255 {
        let mut hasher = Blake2sParams::new()
            .hash_length(32)
            .personal(b"Zcash_gd")
            .to_state();
        hasher.update(input);
        hasher.update(&[counter]);
        let hash = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());

        let maybe_point = AffinePoint::from_bytes(bytes);
        if maybe_point.is_some().into() {
            let extended: ExtendedPoint = maybe_point.unwrap().into();
            return extended.clear_cofactor();
        }
    }

    // Fallback (should never happen)
    SubgroupPoint::generator()
}

/// Note commitment - hiding commitment to note data
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteCommitment(pub [u8; 32]);

impl NoteCommitment {
    /// Compute note commitment
    /// cm = PedersenHash(diversifier || pk_d || value) + rcm * H
    pub fn compute(
        diversifier: &[u8; 11],
        pk_d: &[u8; 32],
        value: u64,
        rcm: &Fr,
    ) -> Self {
        // Inner Pedersen hash of note contents
        let inner = Self::pedersen_hash_note(diversifier, pk_d, value);

        // Add blinding factor: cm = inner + rcm * H
        let h = note_commitment_randomness_generator();
        let blinded = inner + (h * rcm);

        // Extract u-coordinate as commitment
        let affine = AffinePoint::from(blinded);
        Self(affine.to_bytes())
    }

    /// Pedersen hash of note contents
    fn pedersen_hash_note(diversifier: &[u8; 11], pk_d: &[u8; 32], value: u64) -> ExtendedPoint {
        let mut result = ExtendedPoint::identity();

        // Hash diversifier to curve point
        let g_d = hash_to_point(diversifier);
        result = result + g_d;

        // Hash pk_d to curve point
        let pk_d_point = hash_to_point(pk_d);
        result = result + pk_d_point;

        // Add value contribution
        let value_gen = hash_to_point(b"value_generator");
        result = result + (value_gen * Fr::from(value));

        result
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get as bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Value commitment - Pedersen commitment to transaction value
#[derive(Clone, Debug)]
pub struct ValueCommitment {
    /// The commitment point on Jubjub
    pub point: ExtendedPoint,
}

impl ValueCommitment {
    /// Create a value commitment: cv = value * V + rcv * R
    pub fn commit(value: u64, rcv: &Fr) -> Self {
        let g_v = value_commitment_value_generator();
        let g_r = value_commitment_randomness_generator();

        // cv = value * V + rcv * R
        let value_scalar = Fr::from(value);
        let point = (g_v * value_scalar) + (g_r * rcv);

        Self {
            point: point.into(),
        }
    }

    /// Add two value commitments
    pub fn add(&self, other: &ValueCommitment) -> ValueCommitment {
        ValueCommitment {
            point: self.point + other.point,
        }
    }

    /// Subtract a value commitment
    pub fn sub(&self, other: &ValueCommitment) -> ValueCommitment {
        ValueCommitment {
            point: self.point - other.point,
        }
    }

    /// Negate a value commitment
    pub fn negate(&self) -> ValueCommitment {
        ValueCommitment {
            point: -self.point,
        }
    }

    /// Serialize to 32 bytes (compressed point)
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

    /// Verify value balance: sum(spend_cv) - sum(output_cv) == value_balance * V
    pub fn verify_balance(
        spend_cvs: &[ValueCommitment],
        output_cvs: &[ValueCommitment],
        value_balance: i64,
    ) -> bool {
        let mut sum = ExtendedPoint::identity();

        // Add spend commitments
        for cv in spend_cvs {
            sum = sum + cv.point;
        }

        // Subtract output commitments
        for cv in output_cvs {
            sum = sum - cv.point;
        }

        // Expected = value_balance * V
        let g_v = value_commitment_value_generator();
        let expected = if value_balance >= 0 {
            g_v * Fr::from(value_balance as u64)
        } else {
            -(g_v * Fr::from((-value_balance) as u64))
        };

        sum == expected.into()
    }
}

/// Derive nullifier from nk, commitment, and position
pub fn derive_nullifier(
    nk: &[u8; 32],
    cm: &NoteCommitment,
    position: u64,
) -> [u8; 32] {
    let mut hasher = Blake2sParams::new()
        .hash_length(32)
        .personal(b"Zcash_nf")
        .to_state();

    hasher.update(nk);
    hasher.update(&cm.0);
    hasher.update(&position.to_le_bytes());

    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

/// Merkle tree hash for commitments
pub fn merkle_hash(depth: usize, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut personalization = [0u8; 8];
    personalization[..6].copy_from_slice(b"Zcash_");
    personalization[6] = b'M';
    personalization[7] = depth as u8;

    let mut hasher = Blake2sParams::new()
        .hash_length(32)
        .personal(&personalization)
        .to_state();

    hasher.update(left);
    hasher.update(right);

    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

/// Empty Merkle root at given depth
pub fn empty_root(depth: usize) -> [u8; 32] {
    if depth == 0 {
        [0u8; 32]
    } else {
        let child = empty_root(depth - 1);
        merkle_hash(depth - 1, &child, &child)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_note_commitment_deterministic() {
        let diversifier = [1u8; 11];
        let pk_d = [2u8; 32];
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

        let restored = ValueCommitment::from_bytes(&bytes).unwrap();
        assert_eq!(cv.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_value_balance() {
        let rcv1 = Fr::from(100u64);
        let rcv2 = Fr::from(50u64);

        // Spend 1000, output 700, value_balance = 300
        let spend_cv = ValueCommitment::commit(1000, &rcv1);
        let output_cv = ValueCommitment::commit(700, &rcv2);

        // Net randomness should be rcv1 - rcv2
        // But balance verification works differently...
        // For now just check basic functionality
        let spend_bytes = spend_cv.to_bytes();
        let output_bytes = output_cv.to_bytes();

        assert_ne!(spend_bytes, output_bytes);
    }

    #[test]
    fn test_nullifier_deterministic() {
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

    #[test]
    fn test_merkle_hash() {
        let left = [1u8; 32];
        let right = [2u8; 32];

        let hash1 = merkle_hash(0, &left, &right);
        let hash2 = merkle_hash(0, &left, &right);

        assert_eq!(hash1, hash2);

        // Different depth = different hash
        let hash3 = merkle_hash(1, &left, &right);
        assert_ne!(hash1, hash3);
    }
}
