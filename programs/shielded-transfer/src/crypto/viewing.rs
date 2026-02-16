//! Viewing Keys for Selective Disclosure
//!
//! Allow third parties (auditors, regulators, accountants) to view your
//! transactions without being able to spend your funds.
//!
//! Key types:
//! - Full Viewing Key: See all incoming AND outgoing transactions
//! - Incoming Viewing Key: See only incoming transactions
//! - Outgoing Viewing Key: See only outgoing transactions
//! - Payment Disclosure: Prove a specific payment was made

use blake2s_simd::Params as Blake2sParams;
use borsh::{BorshDeserialize, BorshSerialize};

use super::note::Note;

/// Full viewing key - can see all transactions (incoming + outgoing)
/// but cannot spend funds
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct FullViewingKeyData {
    /// Incoming viewing key component (ak)
    pub ak: [u8; 32],

    /// Nullifier deriving key (nk)
    pub nk: [u8; 32],

    /// Outgoing viewing key
    pub ovk: [u8; 32],
}

impl FullViewingKeyData {
    /// Derive from spending key
    pub fn from_spending_key(sk: &[u8; 32]) -> Self {
        // Derive ak (authorization key)
        let ak = derive_key(sk, b"ak");

        // Derive nk (nullifier key)
        let nk = derive_key(sk, b"nk");

        // Derive ovk (outgoing viewing key)
        let ovk = derive_key(sk, b"ovk");

        Self { ak, nk, ovk }
    }

    /// Get incoming viewing key
    pub fn incoming_viewing_key(&self) -> IncomingViewingKeyData {
        IncomingViewingKeyData {
            ivk: derive_ivk(&self.ak, &self.nk),
        }
    }

    /// Get outgoing viewing key
    pub fn outgoing_viewing_key(&self) -> OutgoingViewingKeyData {
        OutgoingViewingKeyData {
            ovk: self.ovk,
        }
    }

    /// Try to decrypt and view a note
    pub fn try_decrypt_note(&self, encrypted: &super::note::EncryptedNote) -> Option<Note> {
        // First try with incoming viewing key
        if let Some(note) = self.incoming_viewing_key().try_decrypt_note(encrypted) {
            return Some(note);
        }

        // Then try with outgoing viewing key
        self.outgoing_viewing_key().try_decrypt_note(encrypted)
    }

    /// Compute nullifier for a note (to check if it's spent)
    pub fn compute_nullifier(&self, note_commitment: &[u8; 32], position: u64) -> [u8; 32] {
        let mut hasher = Blake2sParams::new()
            .hash_length(32)
            .personal(b"YCoin_nf")
            .to_state();

        hasher.update(&self.nk);
        hasher.update(note_commitment);
        hasher.update(&position.to_le_bytes());

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }
}

/// Incoming viewing key - can only see incoming transactions
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct IncomingViewingKeyData {
    /// The incoming viewing key
    pub ivk: [u8; 32],
}

impl IncomingViewingKeyData {
    /// Try to decrypt a note using the incoming viewing key
    pub fn try_decrypt_note(&self, _encrypted: &super::note::EncryptedNote) -> Option<Note> {
        // In a real implementation, this would:
        // 1. Derive the shared secret from ivk and ephemeral_key
        // 2. Derive the decryption key
        // 3. Decrypt the note plaintext
        // 4. Parse and return the note

        // For now, return None - real decryption needs the full note structure
        None
    }

    /// Derive payment address from this viewing key
    pub fn derive_address(&self, diversifier: &[u8; 11]) -> [u8; 32] {
        let hash = Blake2sParams::new()
            .hash_length(32)
            .personal(b"YCoin_PA") // Payment Address
            .to_state()
            .update(&self.ivk)
            .update(diversifier)
            .finalize();

        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }
}

/// Outgoing viewing key - can only see outgoing transactions
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct OutgoingViewingKeyData {
    /// The outgoing viewing key
    pub ovk: [u8; 32],
}

impl OutgoingViewingKeyData {
    /// Try to decrypt a note using the outgoing viewing key
    pub fn try_decrypt_note(&self, _encrypted: &super::note::EncryptedNote) -> Option<Note> {
        // Outgoing notes are encrypted differently
        // The sender stores the decryption info in out_ciphertext
        None
    }
}

/// Payment disclosure - prove that a specific payment was made
/// without revealing your full viewing key
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct PaymentDisclosure {
    /// Transaction ID containing the payment
    pub txid: [u8; 32],

    /// Index of the output in the transaction
    pub output_index: u32,

    /// The note plaintext (decrypted)
    pub note_value: u64,
    pub note_recipient: [u8; 32],
    pub note_memo: Vec<u8>,

    /// Proof that this disclosure is valid
    /// (commitment opens to claimed values)
    pub opening_randomness: [u8; 32],
}

impl PaymentDisclosure {
    /// Create a payment disclosure for a note you sent
    pub fn create(
        txid: [u8; 32],
        output_index: u32,
        note: &Note,
        rcm: &[u8; 32],
    ) -> Self {
        Self {
            txid,
            output_index,
            note_value: note.value,
            note_recipient: note.pk_d,
            note_memo: Vec::new(),
            opening_randomness: *rcm,
        }
    }

    /// Verify that this disclosure matches a commitment
    pub fn verify(&self, commitment: &[u8; 32]) -> bool {
        // Recompute the commitment from disclosed values
        let computed = compute_note_commitment(
            &self.note_recipient,
            self.note_value,
            &self.opening_randomness,
        );

        &computed == commitment
    }
}

/// Viewing key export format (for sharing with auditors)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ViewingKeyExport {
    /// Version of the export format
    pub version: u8,

    /// Type of viewing key
    pub key_type: ViewingKeyType,

    /// The key data
    pub key_data: Vec<u8>,

    /// Optional label
    pub label: String,

    /// Creation timestamp
    pub created_at: u64,

    /// Optional expiration timestamp
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum ViewingKeyType {
    Full = 0,
    Incoming = 1,
    Outgoing = 2,
}

impl ViewingKeyExport {
    /// Create an export for a full viewing key
    pub fn full(fvk: &FullViewingKeyData, label: &str) -> Self {
        Self {
            version: 1,
            key_type: ViewingKeyType::Full,
            key_data: borsh::to_vec(fvk).unwrap_or_default(),
            label: label.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            expires_at: None,
        }
    }

    /// Create an export for incoming viewing key only
    pub fn incoming(ivk: &IncomingViewingKeyData, label: &str) -> Self {
        Self {
            version: 1,
            key_type: ViewingKeyType::Incoming,
            key_data: borsh::to_vec(ivk).unwrap_or_default(),
            label: label.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            expires_at: None,
        }
    }

    /// Set expiration time
    pub fn with_expiration(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Check if the export is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now > expires
        } else {
            false
        }
    }

    /// Encode to a shareable string (base58)
    pub fn to_string(&self) -> String {
        let bytes = borsh::to_vec(self).unwrap_or_default();
        bs58::encode(&bytes).into_string()
    }

    /// Decode from string
    pub fn from_string(s: &str) -> Option<Self> {
        let bytes = bs58::decode(s).into_vec().ok()?;
        borsh::from_slice(&bytes).ok()
    }
}

// Helper functions

fn derive_key(sk: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(b"YCoin_VK")
        .to_state()
        .update(sk)
        .update(domain)
        .finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

fn derive_ivk(ak: &[u8; 32], nk: &[u8; 32]) -> [u8; 32] {
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(b"YCoin_IV")
        .to_state()
        .update(ak)
        .update(nk)
        .finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

fn compute_note_commitment(
    pk_d: &[u8; 32],
    value: u64,
    rcm: &[u8; 32],
) -> [u8; 32] {
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(b"YCoin_NC")
        .to_state()
        .update(pk_d)
        .update(&value.to_le_bytes())
        .update(rcm)
        .finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::ff::Field;

    #[test]
    fn test_full_viewing_key_derivation() {
        let sk = [42u8; 32];
        let fvk = FullViewingKeyData::from_spending_key(&sk);

        assert_ne!(fvk.ak, [0u8; 32]);
        assert_ne!(fvk.nk, [0u8; 32]);
        assert_ne!(fvk.ovk, [0u8; 32]);
    }

    #[test]
    fn test_viewing_key_export() {
        let sk = [42u8; 32];
        let fvk = FullViewingKeyData::from_spending_key(&sk);

        let export = ViewingKeyExport::full(&fvk, "My Tax Auditor");
        let encoded = export.to_string();
        let decoded = ViewingKeyExport::from_string(&encoded).unwrap();

        assert_eq!(decoded.label, "My Tax Auditor");
        assert_eq!(decoded.key_type, ViewingKeyType::Full);
    }

    #[test]
    fn test_payment_disclosure() {
        let txid = [1u8; 32];
        let pk_d = [2u8; 32];
        let rcm_bytes = [3u8; 32];

        // Create a note
        let rcm = jubjub::Fr::from_bytes(&rcm_bytes).unwrap_or(jubjub::Fr::one());
        let note = Note {
            diversifier: [0u8; 11],
            pk_d,
            value: 1000,
            rcm,
            rseed: [0u8; 32],
        };

        // Create disclosure
        let disclosure = PaymentDisclosure::create(txid, 0, &note, &rcm_bytes);

        // Compute commitment
        let commitment = compute_note_commitment(&pk_d, 1000, &rcm_bytes);

        // Verify disclosure
        assert!(disclosure.verify(&commitment));
    }

    #[test]
    fn test_expiration() {
        let sk = [42u8; 32];
        let fvk = FullViewingKeyData::from_spending_key(&sk);

        // Create expired export
        let export = ViewingKeyExport::full(&fvk, "Expired Key")
            .with_expiration(0); // Expired in 1970

        assert!(export.is_expired());

        // Create non-expired export
        let export = ViewingKeyExport::full(&fvk, "Valid Key")
            .with_expiration(u64::MAX);

        assert!(!export.is_expired());
    }
}
