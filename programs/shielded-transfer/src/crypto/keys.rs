//! Key derivation for shielded transactions
//!
//! YaCoin key hierarchy (based on Sapling protocol):
//! - SpendingKey (sk): Master secret, can spend funds
//! - FullViewingKey (fvk): Can view all transactions, derive addresses
//! - IncomingViewingKey (ivk): Can detect incoming payments
//! - OutgoingViewingKey (ovk): Can decrypt outgoing transaction details
//! - Diversifier (d): Creates multiple addresses from same key

use jubjub::{Fr, SubgroupPoint, ExtendedPoint, AffinePoint};
use group::Group;
use group::cofactor::CofactorGroup;
use blake2b_simd::Params as Blake2bParams;
use blake2s_simd::Params as Blake2sParams;

/// Helper to convert SubgroupPoint to AffinePoint
fn subgroup_to_affine(point: &SubgroupPoint) -> AffinePoint {
    let extended: ExtendedPoint = (*point).into();
    AffinePoint::from(extended)
}

/// Domain separators
const PRF_EXPAND_DOMAIN: &[u8; 16] = b"YaCoin_ExpandSed"; // 16 bytes
const CRH_IVK_DOMAIN: &[u8; 8] = b"Zcashivk";

/// Spending key - the master secret
#[derive(Clone)]
pub struct SpendingKey {
    /// 32-byte secret key
    sk: [u8; 32],
}

impl SpendingKey {
    /// Create from random bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { sk: bytes }
    }

    /// Generate from seed using PRF
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut hasher = Blake2bParams::new()
            .hash_length(32)
            .personal(PRF_EXPAND_DOMAIN)
            .to_state();

        hasher.update(seed);
        hasher.update(&[0x00]); // domain for spending key

        let hash = hasher.finalize();
        let mut sk = [0u8; 32];
        sk.copy_from_slice(hash.as_bytes());

        Self { sk }
    }

    /// Get the raw bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.sk
    }

    /// Derive the ask (spend authorizing key) scalar
    pub fn ask(&self) -> Fr {
        let expanded = self.prf_expand(&[0x00]);
        to_scalar(&expanded)
    }

    /// Derive the nsk (nullifier secret key) scalar
    pub fn nsk(&self) -> Fr {
        let expanded = self.prf_expand(&[0x01]);
        to_scalar(&expanded)
    }

    /// Derive the ovk (outgoing viewing key)
    pub fn ovk(&self) -> OutgoingViewingKey {
        let expanded = self.prf_expand(&[0x02]);
        let mut ovk = [0u8; 32];
        ovk.copy_from_slice(&expanded[..32]);
        OutgoingViewingKey { ovk }
    }

    /// PRF expand helper
    fn prf_expand(&self, domain: &[u8]) -> [u8; 64] {
        let mut hasher = Blake2bParams::new()
            .hash_length(64)
            .personal(PRF_EXPAND_DOMAIN)
            .to_state();

        hasher.update(&self.sk);
        hasher.update(domain);

        let hash = hasher.finalize();
        let mut result = [0u8; 64];
        result.copy_from_slice(hash.as_bytes());
        result
    }

    /// Derive full viewing key
    pub fn to_full_viewing_key(&self) -> FullViewingKey {
        let ask = self.ask();
        let nsk = self.nsk();
        let ovk = self.ovk();

        // ak = ask * G (spend authorizing key point)
        let ak = SubgroupPoint::generator() * ask;

        // nk = nsk * G (nullifier deriving key point)
        let nk = SubgroupPoint::generator() * nsk;

        FullViewingKey { ak, nk, ovk }
    }
}

/// Full viewing key - can view all transactions
#[derive(Clone)]
pub struct FullViewingKey {
    /// Spend authorizing key (public)
    pub ak: SubgroupPoint,
    /// Nullifier deriving key (public)
    pub nk: SubgroupPoint,
    /// Outgoing viewing key
    pub ovk: OutgoingViewingKey,
}

impl FullViewingKey {
    /// Derive the incoming viewing key
    pub fn to_incoming_viewing_key(&self) -> IncomingViewingKey {
        let ak_bytes = subgroup_to_affine(&self.ak).to_bytes();
        let nk_bytes = subgroup_to_affine(&self.nk).to_bytes();

        let mut hasher = Blake2sParams::new()
            .hash_length(32)
            .personal(CRH_IVK_DOMAIN)
            .to_state();

        hasher.update(&ak_bytes);
        hasher.update(&nk_bytes);

        let hash = hasher.finalize();
        let mut ivk_bytes = [0u8; 32];
        ivk_bytes.copy_from_slice(hash.as_bytes());

        // Convert to scalar and ensure it's in the valid range
        let ivk = to_scalar(&[ivk_bytes, [0u8; 32]].concat().try_into().unwrap());

        IncomingViewingKey { ivk }
    }

    /// Get ak as bytes
    pub fn ak_bytes(&self) -> [u8; 32] {
        subgroup_to_affine(&self.ak).to_bytes()
    }

    /// Get nk as bytes (for nullifier derivation)
    pub fn nk_bytes(&self) -> [u8; 32] {
        subgroup_to_affine(&self.nk).to_bytes()
    }

    /// Get the outgoing viewing key
    pub fn to_outgoing_viewing_key(&self) -> OutgoingViewingKey {
        self.ovk.clone()
    }
}

/// Incoming viewing key - can detect incoming payments
#[derive(Clone)]
pub struct IncomingViewingKey {
    /// The ivk scalar
    pub ivk: Fr,
}

impl IncomingViewingKey {
    /// Derive payment address from diversifier
    pub fn to_payment_address(&self, diversifier: &Diversifier) -> Option<PaymentAddress> {
        // g_d = diversifier hash to point
        let g_d = diversifier.to_point()?;

        // pk_d = ivk * g_d
        let pk_d = g_d * self.ivk;

        Some(PaymentAddress {
            diversifier: *diversifier,
            pk_d,
        })
    }

    /// Get ivk as bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.ivk.to_bytes()
    }
}

/// Outgoing viewing key - can decrypt outgoing notes
#[derive(Clone)]
pub struct OutgoingViewingKey {
    /// 32-byte ovk
    pub ovk: [u8; 32],
}

impl OutgoingViewingKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { ovk: bytes }
    }

    /// Get as bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.ovk
    }
}

/// Diversifier for creating multiple addresses
#[derive(Clone, Copy)]
pub struct Diversifier(pub [u8; 11]);

impl Diversifier {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 11]) -> Self {
        Self(bytes)
    }

    /// Get as bytes
    pub fn to_bytes(&self) -> [u8; 11] {
        self.0
    }

    /// Hash diversifier to a point on Jubjub (g_d)
    pub fn to_point(&self) -> Option<SubgroupPoint> {
        // Use a hash-to-curve approach
        let mut hasher = Blake2sParams::new()
            .hash_length(32)
            .personal(b"YaCoin_gd")
            .to_state();

        hasher.update(&self.0);
        let hash = hasher.finalize();

        // Try to interpret as a point
        // In production, would use proper hash-to-curve
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());

        let point = jubjub::AffinePoint::from_bytes(bytes);
        if point.is_some().into() {
            let extended: ExtendedPoint = point.unwrap().into();
            // Check if in prime-order subgroup
            Some(SubgroupPoint::from(extended.clear_cofactor()))
        } else {
            // If this diversifier doesn't work, return None
            // Caller should try next diversifier
            None
        }
    }
}

/// Payment address (diversifier + pk_d)
#[derive(Clone)]
pub struct PaymentAddress {
    /// The diversifier
    pub diversifier: Diversifier,
    /// The diversified transmission key
    pub pk_d: SubgroupPoint,
}

impl PaymentAddress {
    /// Serialize to 43 bytes (11 + 32)
    pub fn to_bytes(&self) -> [u8; 43] {
        let mut bytes = [0u8; 43];
        bytes[0..11].copy_from_slice(&self.diversifier.0);
        bytes[11..43].copy_from_slice(&subgroup_to_affine(&self.pk_d).to_bytes());
        bytes
    }

    /// Deserialize from 43 bytes
    pub fn from_bytes(bytes: &[u8; 43]) -> Option<Self> {
        let mut diversifier = [0u8; 11];
        diversifier.copy_from_slice(&bytes[0..11]);

        let mut pk_d_bytes = [0u8; 32];
        pk_d_bytes.copy_from_slice(&bytes[11..43]);

        let pk_d = AffinePoint::from_bytes(pk_d_bytes);
        if pk_d.is_some().into() {
            let extended: ExtendedPoint = pk_d.unwrap().into();
            Some(Self {
                diversifier: Diversifier(diversifier),
                pk_d: SubgroupPoint::from(extended.clear_cofactor()),
            })
        } else {
            None
        }
    }
}

/// Viewing key (for balance queries without spending)
#[derive(Clone)]
pub struct ViewingKey {
    /// Incoming viewing key
    pub ivk: IncomingViewingKey,
    /// Outgoing viewing key
    pub ovk: OutgoingViewingKey,
}

impl ViewingKey {
    /// Create from full viewing key
    pub fn from_full_viewing_key(fvk: &FullViewingKey) -> Self {
        Self {
            ivk: fvk.to_incoming_viewing_key(),
            ovk: fvk.ovk.clone(),
        }
    }

    /// Check if a note is addressed to this viewing key
    pub fn can_decrypt(&self, diversifier: &Diversifier, pk_d: &[u8; 32]) -> bool {
        if let Some(address) = self.ivk.to_payment_address(diversifier) {
            let expected = subgroup_to_affine(&address.pk_d).to_bytes();
            expected == *pk_d
        } else {
            false
        }
    }
}

/// Convert 64 bytes to a Jubjub scalar
fn to_scalar(bytes: &[u8; 64]) -> Fr {
    Fr::from_bytes_wide(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spending_key_derivation() {
        let seed = [1u8; 32];
        let sk = SpendingKey::from_seed(&seed);

        // Should be deterministic
        let sk2 = SpendingKey::from_seed(&seed);
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn test_viewing_key_derivation() {
        let sk = SpendingKey::from_bytes([42u8; 32]);
        let fvk = sk.to_full_viewing_key();
        let ivk = fvk.to_incoming_viewing_key();

        // ivk should be non-zero
        assert_ne!(ivk.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn test_ovk_derivation() {
        let sk = SpendingKey::from_bytes([42u8; 32]);
        let ovk = sk.ovk();

        assert_ne!(ovk.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn test_diversifier() {
        let diversifier = Diversifier([0u8; 11]);

        // Note: Not all diversifiers map to valid points
        // In production, need to find valid diversifiers
        let _point = diversifier.to_point();
    }

    #[test]
    fn test_full_key_hierarchy() {
        // Generate keys
        let sk = SpendingKey::from_seed(b"test seed for yacoin shielded transactions");
        let fvk = sk.to_full_viewing_key();
        let vk = ViewingKey::from_full_viewing_key(&fvk);

        // All should be non-trivial
        assert_ne!(fvk.ak_bytes(), [0u8; 32]);
        assert_ne!(fvk.nk_bytes(), [0u8; 32]);
        assert_ne!(vk.ivk.to_bytes(), [0u8; 32]);
        assert_ne!(vk.ovk.to_bytes(), [0u8; 32]);
    }
}
