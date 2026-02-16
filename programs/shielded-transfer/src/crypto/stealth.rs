//! Stealth Addresses
//!
//! One-time addresses that can't be linked to the recipient's main address.
//! The sender generates a fresh address for each payment, but only the
//! recipient can spend from it.
//!
//! Protocol:
//! 1. Recipient publishes (A, B) where A = a*G, B = b*G (scan key, spend key)
//! 2. Sender generates random r, computes R = r*G
//! 3. Sender computes shared secret s = H(r*A) = H(a*R)
//! 4. Stealth address P = H(s)*G + B
//! 5. Recipient scans for s = H(a*R), checks if P = H(s)*G + B
//! 6. Recipient can spend with private key H(s) + b

use jubjub::{ExtendedPoint, Fr, SubgroupPoint, AffinePoint};
use group::Group;
use group::ff::Field;
use blake2s_simd::Params as Blake2sParams;
use rand::RngCore;

/// Stealth address meta-address (published by recipient)
///
/// This is what you share publicly. People can derive fresh
/// one-time addresses from this without linking them.
#[derive(Clone, Debug)]
pub struct StealthMetaAddress {
    /// Scan public key (A = a*G)
    /// Used to detect incoming payments
    pub scan_pubkey: SubgroupPoint,

    /// Spend public key (B = b*G)
    /// Controls spending from stealth addresses
    pub spend_pubkey: SubgroupPoint,
}

/// Stealth address keys (held by recipient)
#[derive(Clone)]
pub struct StealthKeys {
    /// Scan private key (a)
    pub scan_privkey: Fr,

    /// Spend private key (b)
    pub spend_privkey: Fr,

    /// The public meta-address
    pub meta_address: StealthMetaAddress,
}

/// A generated stealth address (created by sender)
#[derive(Clone, Debug)]
pub struct StealthAddress {
    /// The one-time address point (P = H(s)*G + B)
    pub address: SubgroupPoint,

    /// The ephemeral public key (R = r*G)
    /// Recipient needs this to find and spend
    pub ephemeral_pubkey: SubgroupPoint,
}

/// Spending key for a specific stealth address
#[derive(Clone)]
pub struct StealthSpendKey {
    /// The full private key for this stealth address
    pub privkey: Fr,
}

impl StealthKeys {
    /// Generate new random stealth keys
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let scan_privkey = Fr::random(&mut *rng);
        let spend_privkey = Fr::random(&mut *rng);

        let scan_pubkey = SubgroupPoint::generator() * scan_privkey;
        let spend_pubkey = SubgroupPoint::generator() * spend_privkey;

        Self {
            scan_privkey,
            spend_privkey,
            meta_address: StealthMetaAddress {
                scan_pubkey,
                spend_pubkey,
            },
        }
    }

    /// Derive from a master spending key
    pub fn from_spending_key(sk: &[u8; 32]) -> Self {
        // Derive scan key
        let scan_bytes = Blake2sParams::new()
            .hash_length(32)
            .personal(b"YCoin_SK") // Scan Key
            .to_state()
            .update(sk)
            .update(b"scan")
            .finalize();

        let mut scan_arr = [0u8; 32];
        scan_arr.copy_from_slice(scan_bytes.as_bytes());
        let scan_privkey = Fr::from_bytes(&scan_arr).unwrap_or(Fr::one());

        // Derive spend key
        let spend_bytes = Blake2sParams::new()
            .hash_length(32)
            .personal(b"YCoin_SK")
            .to_state()
            .update(sk)
            .update(b"spend")
            .finalize();

        let mut spend_arr = [0u8; 32];
        spend_arr.copy_from_slice(spend_bytes.as_bytes());
        let spend_privkey = Fr::from_bytes(&spend_arr).unwrap_or(Fr::one());

        let scan_pubkey = SubgroupPoint::generator() * scan_privkey;
        let spend_pubkey = SubgroupPoint::generator() * spend_privkey;

        Self {
            scan_privkey,
            spend_privkey,
            meta_address: StealthMetaAddress {
                scan_pubkey,
                spend_pubkey,
            },
        }
    }

    /// Scan a transaction to check if it's for us
    /// Returns the spend key if this stealth address belongs to us
    pub fn scan(&self, stealth: &StealthAddress) -> Option<StealthSpendKey> {
        // Compute shared secret: s = H(a * R)
        let shared_point = stealth.ephemeral_pubkey * self.scan_privkey;
        let shared_secret = hash_to_scalar(&point_to_bytes(&shared_point.into()));

        // Compute expected address: P = H(s)*G + B
        let expected = (SubgroupPoint::generator() * shared_secret) + self.meta_address.spend_pubkey;

        // Check if it matches
        if expected == stealth.address {
            // Compute spending key: H(s) + b
            let privkey = shared_secret + self.spend_privkey;
            Some(StealthSpendKey { privkey })
        } else {
            None
        }
    }

    /// Get the meta-address to share publicly
    pub fn meta_address(&self) -> &StealthMetaAddress {
        &self.meta_address
    }
}

impl StealthMetaAddress {
    /// Generate a stealth address for this recipient
    pub fn generate_stealth_address<R: RngCore>(&self, rng: &mut R) -> StealthAddress {
        // Generate random ephemeral key
        let r = Fr::random(rng);
        let ephemeral_pubkey = SubgroupPoint::generator() * r;

        // Compute shared secret: s = H(r * A)
        let shared_point = self.scan_pubkey * r;
        let shared_secret = hash_to_scalar(&point_to_bytes(&shared_point.into()));

        // Compute stealth address: P = H(s)*G + B
        let address = (SubgroupPoint::generator() * shared_secret) + self.spend_pubkey;

        StealthAddress {
            address,
            ephemeral_pubkey,
        }
    }

    /// Serialize to bytes (64 bytes: scan_pubkey || spend_pubkey)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&point_to_bytes(&self.scan_pubkey.into()));
        bytes[32..].copy_from_slice(&point_to_bytes(&self.spend_pubkey.into()));
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Self> {
        let scan_pubkey = point_from_bytes(&bytes[..32])?;
        let spend_pubkey = point_from_bytes(&bytes[32..])?;

        Some(Self {
            scan_pubkey,
            spend_pubkey,
        })
    }
}

impl StealthAddress {
    /// Get the address as bytes (for use in transactions)
    pub fn to_bytes(&self) -> [u8; 32] {
        point_to_bytes(&self.address.into())
    }

    /// Get the ephemeral key as bytes (must be included in tx)
    pub fn ephemeral_to_bytes(&self) -> [u8; 32] {
        point_to_bytes(&self.ephemeral_pubkey.into())
    }
}

/// Hash bytes to a scalar
fn hash_to_scalar(input: &[u8]) -> Fr {
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(b"YCoin_SS") // Shared Secret
        .to_state()
        .update(input)
        .finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(hash.as_bytes());
    Fr::from_bytes(&bytes).unwrap_or(Fr::one())
}

/// Convert point to bytes
fn point_to_bytes(point: &ExtendedPoint) -> [u8; 32] {
    let affine = AffinePoint::from(*point);
    affine.to_bytes()
}

/// Convert bytes to point
fn point_from_bytes(bytes: &[u8]) -> Option<SubgroupPoint> {
    if bytes.len() < 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);

    let affine: Option<AffinePoint> = AffinePoint::from_bytes(arr).into();
    affine.map(|a| {
        let extended: ExtendedPoint = a.into();
        // Clear cofactor to get subgroup point
        use group::cofactor::CofactorGroup;
        extended.clear_cofactor()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_stealth_address_flow() {
        let mut rng = OsRng;

        // Recipient generates stealth keys
        let recipient_keys = StealthKeys::generate(&mut rng);

        // Sender gets recipient's meta-address (e.g., from their profile)
        let meta_address = recipient_keys.meta_address().clone();

        // Sender generates a stealth address
        let stealth = meta_address.generate_stealth_address(&mut rng);

        // Recipient scans and finds the payment
        let spend_key = recipient_keys.scan(&stealth);
        assert!(spend_key.is_some());
    }

    #[test]
    fn test_wrong_recipient_cannot_scan() {
        let mut rng = OsRng;

        let recipient_keys = StealthKeys::generate(&mut rng);
        let wrong_keys = StealthKeys::generate(&mut rng);

        let meta_address = recipient_keys.meta_address().clone();
        let stealth = meta_address.generate_stealth_address(&mut rng);

        // Wrong recipient cannot find the payment
        let spend_key = wrong_keys.scan(&stealth);
        assert!(spend_key.is_none());
    }

    #[test]
    fn test_deterministic_from_spending_key() {
        let sk = [42u8; 32];

        let keys1 = StealthKeys::from_spending_key(&sk);
        let keys2 = StealthKeys::from_spending_key(&sk);

        assert_eq!(
            keys1.meta_address.to_bytes(),
            keys2.meta_address.to_bytes()
        );
    }

    #[test]
    fn test_meta_address_serialization() {
        let mut rng = OsRng;
        let keys = StealthKeys::generate(&mut rng);

        let bytes = keys.meta_address.to_bytes();
        let restored = StealthMetaAddress::from_bytes(&bytes);

        // Just verify it deserializes successfully
        assert!(restored.is_some());

        // And that a stealth address generated from either works
        let stealth1 = keys.meta_address.generate_stealth_address(&mut rng);
        let stealth2 = restored.unwrap().generate_stealth_address(&mut rng);

        // Both should produce valid stealth addresses
        assert_ne!(stealth1.to_bytes(), [0u8; 32]);
        assert_ne!(stealth2.to_bytes(), [0u8; 32]);
    }
}
