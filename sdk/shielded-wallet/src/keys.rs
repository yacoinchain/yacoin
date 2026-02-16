//! Key management for shielded wallets
//!
//! Provides functionality for generating and managing shielded keys and addresses.

use crate::error::{WalletError, WalletResult};
use yacoin_shielded_transfer::crypto::keys::{
    SpendingKey, FullViewingKey, IncomingViewingKey, OutgoingViewingKey,
    Diversifier,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// A shielded payment address
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedAddress {
    /// The diversifier (11 bytes)
    pub diversifier: [u8; 11],
    /// The diversified transmission key (32 bytes)
    pub pk_d: [u8; 32],
}

impl ShieldedAddress {
    /// Create from raw bytes
    pub fn from_bytes(diversifier: [u8; 11], pk_d: [u8; 32]) -> Self {
        Self { diversifier, pk_d }
    }

    /// Encode as a bech32 address string
    pub fn to_string(&self) -> String {
        // Simple hex encoding for now
        // In production, use bech32 with "ys" prefix
        format!("ys1{}{}", hex::encode(self.diversifier), hex::encode(self.pk_d))
    }

    /// Parse from string
    pub fn from_string(s: &str) -> WalletResult<Self> {
        if !s.starts_with("ys1") || s.len() != 89 {
            return Err(WalletError::InvalidAddress);
        }

        let hex_part = &s[3..];
        let bytes = hex::decode(hex_part).map_err(|_| WalletError::InvalidAddress)?;

        if bytes.len() != 43 {
            return Err(WalletError::InvalidAddress);
        }

        let mut diversifier = [0u8; 11];
        let mut pk_d = [0u8; 32];
        diversifier.copy_from_slice(&bytes[0..11]);
        pk_d.copy_from_slice(&bytes[11..43]);

        Ok(Self { diversifier, pk_d })
    }
}

/// A viewing key for scanning transactions
#[derive(Clone)]
pub struct ViewingKey {
    /// The incoming viewing key
    pub ivk: IncomingViewingKey,
    /// The outgoing viewing key
    pub ovk: OutgoingViewingKey,
}

impl ViewingKey {
    /// Create from a full viewing key
    pub fn from_full_viewing_key(fvk: &FullViewingKey) -> Self {
        Self {
            ivk: fvk.to_incoming_viewing_key(),
            ovk: fvk.to_outgoing_viewing_key(),
        }
    }

    /// Get the incoming viewing key bytes
    pub fn ivk_bytes(&self) -> [u8; 32] {
        self.ivk.ivk.to_bytes()
    }

    /// Get the outgoing viewing key bytes
    pub fn ovk_bytes(&self) -> [u8; 32] {
        self.ovk.ovk
    }
}

/// Extended spending key with derivation support
#[derive(Clone)]
pub struct ExtendedSpendingKey {
    /// The raw spending key
    pub spending_key: SpendingKey,
    /// Chain code for derivation
    pub chain_code: [u8; 32],
    /// Derivation depth
    pub depth: u8,
    /// Parent fingerprint
    pub parent_fingerprint: [u8; 4],
    /// Child index
    pub child_index: u32,
}

impl ExtendedSpendingKey {
    /// Generate a new random extended spending key
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let spending_key = SpendingKey::from_bytes(seed);

        let mut chain_code = [0u8; 32];
        rng.fill_bytes(&mut chain_code);

        Self {
            spending_key,
            chain_code,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_index: 0,
        }
    }

    /// Create from seed bytes
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        use blake2b_simd::Params;

        // Derive spending key and chain code from seed
        let hash = Params::new()
            .hash_length(64)
            .personal(b"YaCoin_ZIP32____")
            .to_state()
            .update(seed)
            .finalize();

        let hash_bytes = hash.as_bytes();

        let mut sk_bytes = [0u8; 32];
        let mut chain_code = [0u8; 32];
        sk_bytes.copy_from_slice(&hash_bytes[0..32]);
        chain_code.copy_from_slice(&hash_bytes[32..64]);

        Self {
            spending_key: SpendingKey::from_bytes(sk_bytes),
            chain_code,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_index: 0,
        }
    }

    /// Get the full viewing key
    pub fn to_full_viewing_key(&self) -> FullViewingKey {
        self.spending_key.to_full_viewing_key()
    }

    /// Get a payment address at the given diversifier index
    /// Returns (ShieldedAddress, actual_index_used)
    pub fn get_address(&self, diversifier_index: u64) -> WalletResult<ShieldedAddress> {
        let (addr, _) = self.get_address_with_index(diversifier_index)?;
        Ok(addr)
    }

    /// Get a payment address at the given diversifier index, returning the actual index used
    pub fn get_address_with_index(&self, diversifier_index: u64) -> WalletResult<(ShieldedAddress, u64)> {
        let fvk = self.to_full_viewing_key();
        let ivk = fvk.to_incoming_viewing_key();

        // Try to find a valid diversifier
        for i in diversifier_index..(diversifier_index + 100) {
            let diversifier = derive_diversifier(i);
            if let Some(addr) = ivk.to_payment_address(&diversifier) {
                // Extract pk_d bytes from the serialized address (bytes 11-43)
                let addr_bytes = addr.to_bytes();
                let mut pk_d = [0u8; 32];
                pk_d.copy_from_slice(&addr_bytes[11..43]);

                return Ok((ShieldedAddress {
                    diversifier: diversifier.0,
                    pk_d,
                }, i));
            }
        }

        Err(WalletError::InvalidAddress)
    }
}

/// Derive a diversifier from an index
fn derive_diversifier(index: u64) -> Diversifier {
    use blake2b_simd::Params;

    let hash = Params::new()
        .hash_length(11)
        .personal(b"YaCoin_d")
        .to_state()
        .update(&index.to_le_bytes())
        .finalize();

    let mut diversifier = [0u8; 11];
    diversifier.copy_from_slice(hash.as_bytes());
    Diversifier(diversifier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_generate_spending_key() {
        let esk = ExtendedSpendingKey::generate(&mut OsRng);
        assert_eq!(esk.depth, 0);
    }

    #[test]
    fn test_from_seed() {
        let seed = [42u8; 32];
        let esk1 = ExtendedSpendingKey::from_seed(&seed);
        let esk2 = ExtendedSpendingKey::from_seed(&seed);

        // Same seed should produce same keys
        let fvk1 = esk1.to_full_viewing_key();
        let fvk2 = esk2.to_full_viewing_key();
        assert_eq!(fvk1.ak_bytes(), fvk2.ak_bytes());
    }

    #[test]
    fn test_address_generation() {
        let seed = [1u8; 32];
        let esk = ExtendedSpendingKey::from_seed(&seed);

        // Should be able to generate addresses
        let addr = esk.get_address(0);
        assert!(addr.is_ok());
    }

    #[test]
    fn test_address_encoding() {
        let seed = [2u8; 32];
        let esk = ExtendedSpendingKey::from_seed(&seed);
        let addr = esk.get_address(0).unwrap();

        let encoded = addr.to_string();
        assert!(encoded.starts_with("ys1"));

        let decoded = ShieldedAddress::from_string(&encoded).unwrap();
        assert_eq!(addr.diversifier, decoded.diversifier);
        assert_eq!(addr.pk_d, decoded.pk_d);
    }
}
