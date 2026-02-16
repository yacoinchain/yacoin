//! Encrypted Memos
//!
//! Attach private messages to shielded transactions.
//! Only the recipient can decrypt the memo.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use blake2s_simd::Params as Blake2sParams;

/// Maximum memo size (512 bytes like Zcash)
pub const MAX_MEMO_SIZE: usize = 512;

/// Encrypted memo attached to a shielded note
#[derive(Clone, Debug)]
pub struct EncryptedMemo {
    /// The encrypted memo content
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: [u8; 12],
}

impl EncryptedMemo {
    /// Encrypt a memo for a recipient
    ///
    /// The memo is encrypted using a key derived from the shared secret
    /// (ephemeral_secret * pk_d), so only the recipient can decrypt.
    pub fn encrypt(
        memo: &[u8],
        shared_secret: &[u8; 32],
    ) -> Self {
        // Derive memo encryption key from shared secret
        let key = derive_memo_key(shared_secret);

        // Generate nonce from shared secret (deterministic for same secret)
        let nonce_bytes = derive_memo_nonce(shared_secret);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Pad memo to fixed size to hide length
        let mut padded = [0u8; MAX_MEMO_SIZE];
        let len = memo.len().min(MAX_MEMO_SIZE);
        padded[..len].copy_from_slice(&memo[..len]);

        // Encrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .expect("Invalid key length");
        let ciphertext = cipher.encrypt(nonce, padded.as_ref())
            .expect("Encryption failed");

        Self {
            ciphertext,
            nonce: nonce_bytes,
        }
    }

    /// Decrypt a memo using the shared secret
    pub fn decrypt(&self, shared_secret: &[u8; 32]) -> Option<Vec<u8>> {
        let key = derive_memo_key(shared_secret);
        let nonce = Nonce::from_slice(&self.nonce);

        let cipher = ChaCha20Poly1305::new_from_slice(&key).ok()?;
        let plaintext = cipher.decrypt(nonce, self.ciphertext.as_ref()).ok()?;

        // Strip trailing zeros (padding)
        let end = plaintext.iter()
            .rposition(|&b| b != 0)
            .map(|i| i + 1)
            .unwrap_or(0);

        Some(plaintext[..end].to_vec())
    }

    /// Create an empty memo (no message)
    pub fn empty() -> Self {
        Self {
            ciphertext: vec![0u8; MAX_MEMO_SIZE + 16], // +16 for auth tag
            nonce: [0u8; 12],
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12 + self.ciphertext.len());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[..12]);
        let ciphertext = bytes[12..].to_vec();

        Some(Self { ciphertext, nonce })
    }
}

/// Derive memo encryption key from shared secret
fn derive_memo_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(b"YCoin_MK") // Memo Key
        .to_state()
        .update(shared_secret)
        .finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    key
}

/// Derive memo nonce from shared secret
fn derive_memo_nonce(shared_secret: &[u8; 32]) -> [u8; 12] {
    let hash = Blake2sParams::new()
        .hash_length(12)
        .personal(b"YCoin_MN") // Memo Nonce
        .to_state()
        .update(shared_secret)
        .finalize();

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(hash.as_bytes());
    nonce
}

/// Standard memo types (like Zcash)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemoType {
    /// Empty memo
    Empty,
    /// UTF-8 text message
    Text(String),
    /// Arbitrary binary data
    Binary(Vec<u8>),
    /// Payment request reference
    PaymentRef([u8; 32]),
    /// Refund address (for returns)
    RefundAddress(Vec<u8>),
}

impl MemoType {
    /// Encode memo to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            MemoType::Empty => vec![0xF6], // Empty marker (like Zcash)
            MemoType::Text(s) => {
                let mut bytes = vec![0xF5]; // Text marker
                bytes.extend_from_slice(s.as_bytes());
                bytes
            }
            MemoType::Binary(data) => {
                let mut bytes = vec![0xF4]; // Binary marker
                bytes.extend_from_slice(data);
                bytes
            }
            MemoType::PaymentRef(ref_id) => {
                let mut bytes = vec![0xF3]; // Payment ref marker
                bytes.extend_from_slice(ref_id);
                bytes
            }
            MemoType::RefundAddress(addr) => {
                let mut bytes = vec![0xF2]; // Refund marker
                bytes.extend_from_slice(addr);
                bytes
            }
        }
    }

    /// Decode memo from bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return MemoType::Empty;
        }

        match bytes[0] {
            0xF6 => MemoType::Empty,
            0xF5 => {
                let text = String::from_utf8_lossy(&bytes[1..]).to_string();
                MemoType::Text(text)
            }
            0xF4 => MemoType::Binary(bytes[1..].to_vec()),
            0xF3 if bytes.len() >= 33 => {
                let mut ref_id = [0u8; 32];
                ref_id.copy_from_slice(&bytes[1..33]);
                MemoType::PaymentRef(ref_id)
            }
            0xF2 => MemoType::RefundAddress(bytes[1..].to_vec()),
            _ => {
                // Try to parse as UTF-8 text (legacy format)
                if let Ok(text) = String::from_utf8(bytes.to_vec()) {
                    MemoType::Text(text)
                } else {
                    MemoType::Binary(bytes.to_vec())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memo_encrypt_decrypt() {
        let shared_secret = [42u8; 32];
        let memo = b"Hello, this is a private message!";

        let encrypted = EncryptedMemo::encrypt(memo, &shared_secret);
        let decrypted = encrypted.decrypt(&shared_secret).unwrap();

        assert_eq!(decrypted, memo);
    }

    #[test]
    fn test_wrong_key_fails() {
        let shared_secret = [42u8; 32];
        let wrong_secret = [99u8; 32];
        let memo = b"Secret message";

        let encrypted = EncryptedMemo::encrypt(memo, &shared_secret);
        let result = encrypted.decrypt(&wrong_secret);

        assert!(result.is_none());
    }

    #[test]
    fn test_memo_serialization() {
        let shared_secret = [42u8; 32];
        let memo = b"Test memo";

        let encrypted = EncryptedMemo::encrypt(memo, &shared_secret);
        let bytes = encrypted.to_bytes();
        let restored = EncryptedMemo::from_bytes(&bytes).unwrap();

        assert_eq!(encrypted.nonce, restored.nonce);
        assert_eq!(encrypted.ciphertext, restored.ciphertext);
    }

    #[test]
    fn test_memo_types() {
        let text = MemoType::Text("Hello".to_string());
        let restored = MemoType::from_bytes(&text.to_bytes());
        assert_eq!(text, restored);

        let binary = MemoType::Binary(vec![1, 2, 3, 4]);
        let restored = MemoType::from_bytes(&binary.to_bytes());
        assert_eq!(binary, restored);

        let payment = MemoType::PaymentRef([99u8; 32]);
        let restored = MemoType::from_bytes(&payment.to_bytes());
        assert_eq!(payment, restored);
    }
}
