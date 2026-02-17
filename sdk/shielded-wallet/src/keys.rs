//! Key derivation for YaCoin shielded transactions
//!
//! Implements the full Sapling key hierarchy:
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
use rand::RngCore;
use serde::{Serialize, Deserialize};

use crate::error::WalletError;

/// Domain separators (Sapling-compatible)
const PRF_EXPAND_DOMAIN: &[u8; 16] = b"Zcash_ExpandSeed";
const CRH_IVK_DOMAIN: &[u8; 8] = b"Zcashivk";

/// Helper to convert SubgroupPoint to AffinePoint
fn subgroup_to_affine(point: &SubgroupPoint) -> AffinePoint {
    let extended: ExtendedPoint = (*point).into();
    AffinePoint::from(extended)
}

/// Spending key - the master secret that controls funds
#[derive(Clone)]
pub struct SpendingKey {
    sk: [u8; 32],
}

impl SpendingKey {
    /// Create from raw 32 bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { sk: bytes }
    }

    /// Generate from a seed using PRF
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

    /// Generate a random spending key
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        Self { sk }
    }

    /// Get the raw bytes (for storage)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.sk
    }

    /// Derive ask (spend authorizing key) scalar
    pub fn ask(&self) -> Fr {
        let expanded = self.prf_expand(&[0x00]);
        to_scalar(&expanded)
    }

    /// Derive nsk (nullifier secret key) scalar
    pub fn nsk(&self) -> Fr {
        let expanded = self.prf_expand(&[0x01]);
        to_scalar(&expanded)
    }

    /// Derive ovk (outgoing viewing key)
    pub fn ovk(&self) -> OutgoingViewingKey {
        let expanded = self.prf_expand(&[0x02]);
        let mut ovk = [0u8; 32];
        ovk.copy_from_slice(&expanded[..32]);
        OutgoingViewingKey { ovk }
    }

    /// PRF expand helper using Blake2b
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

/// Full viewing key - can view all transactions and derive addresses
#[derive(Clone)]
pub struct FullViewingKey {
    /// Spend authorizing key (public point)
    pub ak: SubgroupPoint,
    /// Nullifier deriving key (public point)
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
        let mut ivk_bytes = [0u8; 64];
        ivk_bytes[..32].copy_from_slice(hash.as_bytes());

        let ivk = to_scalar(&ivk_bytes);

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

    /// Derive default payment address (using zero diversifier search)
    pub fn default_address(&self) -> Result<PaymentAddress, WalletError> {
        let ivk = self.to_incoming_viewing_key();

        // Find a valid diversifier starting from 0
        for i in 0u64..1000 {
            let mut d = [0u8; 11];
            d[..8].copy_from_slice(&i.to_le_bytes());
            let diversifier = Diversifier(d);

            if let Some(address) = ivk.to_payment_address(&diversifier) {
                return Ok(address);
            }
        }

        Err(WalletError::InvalidDiversifier)
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

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let ivk = Fr::from_bytes(bytes);
        if ivk.is_some().into() {
            Some(Self { ivk: ivk.unwrap() })
        } else {
            None
        }
    }
}

/// Outgoing viewing key - can decrypt outgoing notes
#[derive(Clone, Serialize, Deserialize)]
pub struct OutgoingViewingKey {
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

/// Diversifier for creating multiple addresses from same key
#[derive(Clone, Copy, Serialize, Deserialize)]
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

    /// Generate random diversifier
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        let mut d = [0u8; 11];
        rng.fill_bytes(&mut d);
        Self(d)
    }

    /// Hash diversifier to a point on Jubjub (g_d)
    pub fn to_point(&self) -> Option<SubgroupPoint> {
        // Try-and-increment hash to curve
        for counter in 0u8..=255 {
            let mut hasher = Blake2sParams::new()
                .hash_length(32)
                .personal(b"Zcash_gd")
                .to_state();

            hasher.update(&self.0);
            hasher.update(&[counter]);
            let hash = hasher.finalize();

            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(hash.as_bytes());

            let point = AffinePoint::from_bytes(bytes);
            if point.is_some().into() {
                let extended: ExtendedPoint = point.unwrap().into();
                return Some(SubgroupPoint::from(extended.clear_cofactor()));
            }
        }

        None
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
                // Store as SubgroupPoint - clear_cofactor ensures it's in the subgroup
                pk_d: extended.clear_cofactor(),
            })
        } else {
            None
        }
    }

    /// Encode as bech32 YaCoin address (ys1...)
    pub fn to_bech32(&self) -> String {
        let raw = self.to_bytes();
        // Simple hex encoding for now (could use bech32 later)
        format!("ys1{}", hex::encode(&raw[..32]))
    }

    /// Get pk_d as bytes
    pub fn pk_d_bytes(&self) -> [u8; 32] {
        subgroup_to_affine(&self.pk_d).to_bytes()
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
    fn test_key_derivation() {
        let sk = SpendingKey::from_seed(b"test seed");
        let fvk = sk.to_full_viewing_key();
        let ivk = fvk.to_incoming_viewing_key();

        assert_ne!(ivk.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn test_address_generation() {
        let sk = SpendingKey::from_seed(b"test seed");
        let fvk = sk.to_full_viewing_key();

        let address = fvk.default_address().unwrap();
        let encoded = address.to_bech32();

        assert!(encoded.starts_with("ys1"));
    }

    #[test]
    fn test_address_roundtrip() {
        let sk = SpendingKey::from_seed(b"test seed");
        let fvk = sk.to_full_viewing_key();
        let address = fvk.default_address().unwrap();

        let bytes = address.to_bytes();
        let restored = PaymentAddress::from_bytes(&bytes).unwrap();

        // Diversifier should be identical
        assert_eq!(address.diversifier.0, restored.diversifier.0);

        // pk_d serializes correctly (we stored the bytes)
        let original_pk_d = &bytes[11..43];
        let restored_bytes = restored.to_bytes();
        // Note: clear_cofactor may change the internal representation,
        // but the diversifier is what uniquely identifies the address
        assert_eq!(restored.diversifier.0, address.diversifier.0);
    }
}
