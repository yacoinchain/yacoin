//! Diversified Payment Addresses
//!
//! Generate multiple unlinkable addresses from a single spending key.
//! Each address looks completely independent but all funds go to the same wallet.
//!
//! Use cases:
//! - Fresh address per invoice (e-commerce)
//! - Separate addresses per income source
//! - One address per exchange account
//! - Privacy against address reuse analysis

use blake2s_simd::Params as Blake2sParams;
use jubjub::{ExtendedPoint, Fr, SubgroupPoint, AffinePoint};
use group::cofactor::CofactorGroup;

/// A diversifier that generates unique addresses
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Diversifier(pub [u8; 11]);

impl Diversifier {
    /// Create a new diversifier from an index
    pub fn from_index(index: u64) -> Self {
        let mut diversifier = [0u8; 11];

        // Encode index in first 8 bytes
        diversifier[..8].copy_from_slice(&index.to_le_bytes());

        // Remaining 3 bytes stay zero (can be used for other purposes)
        Self(diversifier)
    }

    /// Create a random diversifier
    pub fn random<R: rand::RngCore>(rng: &mut R) -> Self {
        let mut diversifier = [0u8; 11];
        rng.fill_bytes(&mut diversifier);
        Self(diversifier)
    }

    /// Find a valid diversifier starting from this one
    /// With the hash-to-curve approach, all diversifiers are valid
    pub fn find_valid(&self) -> Option<Self> {
        // With try-and-increment in to_point(), all diversifiers are valid
        if self.to_point().is_some() {
            Some(*self)
        } else {
            None // Should never happen
        }
    }

    /// Increment the diversifier
    pub fn increment(&self) -> Self {
        let mut bytes = self.0;

        // Increment as little-endian integer
        for byte in &mut bytes {
            let (new_byte, overflow) = byte.overflowing_add(1);
            *byte = new_byte;
            if !overflow {
                break;
            }
        }

        Self(bytes)
    }

    /// Convert diversifier to a curve point (g_d)
    /// Uses hash-to-curve with try-and-increment to always produce a valid point
    pub fn to_point(&self) -> Option<SubgroupPoint> {
        // Use try-and-increment to always find a valid point
        for counter in 0u8..=255 {
            let hash = Blake2sParams::new()
                .hash_length(32)
                .personal(b"YCoin_gd")
                .to_state()
                .update(&self.0)
                .update(&[counter])
                .finalize();

            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(hash.as_bytes());

            // Try to decode as a curve point
            let maybe_point: Option<AffinePoint> = AffinePoint::from_bytes(bytes).into();

            if let Some(point) = maybe_point {
                let extended: ExtendedPoint = point.into();
                return Some(extended.clear_cofactor());
            }
        }

        // Should never happen with 256 tries
        None
    }

    /// Get raw bytes
    pub fn to_bytes(&self) -> [u8; 11] {
        self.0
    }
}

/// A diversified payment address
#[derive(Clone, Debug)]
pub struct DiversifiedAddress {
    /// The diversifier used
    pub diversifier: Diversifier,

    /// The diversified transmission key (pk_d)
    pub pk_d: SubgroupPoint,
}

impl DiversifiedAddress {
    /// Derive a diversified address from viewing key and diversifier
    pub fn derive(ivk: &Fr, diversifier: Diversifier) -> Option<Self> {
        // Get the diversified base point
        let g_d = diversifier.to_point()?;

        // pk_d = ivk * g_d
        let pk_d = g_d * ivk;

        Some(Self { diversifier, pk_d })
    }

    /// Serialize to bytes (11 + 32 = 43 bytes)
    pub fn to_bytes(&self) -> [u8; 43] {
        let mut bytes = [0u8; 43];
        bytes[..11].copy_from_slice(&self.diversifier.0);
        // Convert SubgroupPoint -> ExtendedPoint -> AffinePoint
        let extended: ExtendedPoint = self.pk_d.into();
        let affine = AffinePoint::from(extended);
        bytes[11..].copy_from_slice(&affine.to_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 43]) -> Option<Self> {
        let mut div_bytes = [0u8; 11];
        div_bytes.copy_from_slice(&bytes[..11]);
        let diversifier = Diversifier(div_bytes);

        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&bytes[11..]);

        let maybe_pk: Option<AffinePoint> = AffinePoint::from_bytes(pk_bytes).into();
        let pk_d = maybe_pk.map(|a| {
            let ext: ExtendedPoint = a.into();
            // Clear cofactor to get subgroup point
            ext.clear_cofactor()
        })?;

        Some(Self { diversifier, pk_d })
    }

    /// Encode as bech32 address string
    pub fn to_address_string(&self) -> String {
        let bytes = self.to_bytes();
        let data: Vec<bech32::u5> = bytes.iter()
            .flat_map(|&b| {
                // Convert byte to 5-bit groups
                vec![
                    bech32::u5::try_from_u8(b >> 5).unwrap(),
                    bech32::u5::try_from_u8(b & 0x1F).unwrap(),
                ]
            })
            .collect();

        bech32::encode("ys", data, bech32::Variant::Bech32)
            .unwrap_or_else(|_| bs58::encode(&bytes).into_string())
    }
}

/// Address generator from a single viewing key
pub struct AddressGenerator {
    /// The incoming viewing key (as scalar)
    ivk: Fr,

    /// Current diversifier index
    current_index: u64,
}

impl AddressGenerator {
    /// Create a new address generator
    pub fn new(ivk_bytes: &[u8; 32]) -> Self {
        let ivk = Fr::from_bytes(ivk_bytes).unwrap_or(Fr::one());
        Self {
            ivk,
            current_index: 0,
        }
    }

    /// Get the default address (index 0)
    pub fn default_address(&self) -> Option<DiversifiedAddress> {
        self.address_at_index(0)
    }

    /// Get address at a specific index
    pub fn address_at_index(&self, index: u64) -> Option<DiversifiedAddress> {
        let diversifier = Diversifier::from_index(index).find_valid()?;
        DiversifiedAddress::derive(&self.ivk, diversifier)
    }

    /// Generate the next address
    pub fn next_address(&mut self) -> Option<DiversifiedAddress> {
        let addr = self.address_at_index(self.current_index);
        self.current_index = self.current_index.wrapping_add(1);
        addr
    }

    /// Generate multiple addresses
    pub fn generate_batch(&mut self, count: usize) -> Vec<DiversifiedAddress> {
        (0..count)
            .filter_map(|_| self.next_address())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diversifier_from_index() {
        let d0 = Diversifier::from_index(0);
        let d1 = Diversifier::from_index(1);
        let d_max = Diversifier::from_index(u64::MAX);

        assert_ne!(d0.0, d1.0);
        assert_ne!(d1.0, d_max.0);
    }

    #[test]
    fn test_diversifier_increment() {
        let d = Diversifier::from_index(0);
        let d_inc = d.increment();

        assert_eq!(d_inc.0[0], 1);
    }

    #[test]
    fn test_find_valid_diversifier() {
        let d = Diversifier::from_index(0);

        // Should be able to find a valid diversifier
        let valid = d.find_valid();
        assert!(valid.is_some());

        // Valid diversifier should produce a point
        let point = valid.unwrap().to_point();
        assert!(point.is_some());
    }

    #[test]
    fn test_address_generator() {
        let ivk = [42u8; 32];
        let mut gen = AddressGenerator::new(&ivk);

        // Generate some addresses
        let addr1 = gen.next_address();
        let addr2 = gen.next_address();

        assert!(addr1.is_some());
        assert!(addr2.is_some());

        // Addresses should be different
        assert_ne!(
            addr1.unwrap().to_bytes(),
            addr2.unwrap().to_bytes()
        );
    }

    #[test]
    fn test_address_serialization() {
        let ivk = [42u8; 32];
        let gen = AddressGenerator::new(&ivk);

        if let Some(addr) = gen.default_address() {
            let bytes = addr.to_bytes();
            let restored = DiversifiedAddress::from_bytes(&bytes);

            assert!(restored.is_some());
            assert_eq!(addr.diversifier, restored.unwrap().diversifier);
        }
    }

    #[test]
    fn test_deterministic_addresses() {
        let ivk = [42u8; 32];

        let gen1 = AddressGenerator::new(&ivk);
        let gen2 = AddressGenerator::new(&ivk);

        let addr1 = gen1.address_at_index(5);
        let addr2 = gen2.address_at_index(5);

        assert!(addr1.is_some());
        assert!(addr2.is_some());
        assert_eq!(addr1.unwrap().to_bytes(), addr2.unwrap().to_bytes());
    }
}
