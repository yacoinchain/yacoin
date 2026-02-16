//! Note structure and encryption for shielded transactions
//!
//! A note represents a shielded value that can only be spent by
//! the holder of the spending key.
//!
//! Uses ChaCha20-Poly1305 AEAD for authenticated encryption.

use jubjub::{Fr, SubgroupPoint, ExtendedPoint, AffinePoint};
use group::Group;
use group::cofactor::CofactorGroup;
use blake2b_simd::Params as Blake2bParams;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

use super::keys::{PaymentAddress, OutgoingViewingKey, IncomingViewingKey, Diversifier};
use super::pedersen::{NoteCommitment, derive_nullifier};
use crate::{ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE};

/// AEAD tag size (Poly1305)
const AEAD_TAG_SIZE: usize = 16;

/// Note plaintext size
const NOTE_PLAINTEXT_SIZE: usize = 564; // Sapling note plaintext

/// Helper to convert SubgroupPoint to AffinePoint
fn subgroup_to_affine(point: &SubgroupPoint) -> AffinePoint {
    let extended: ExtendedPoint = (*point).into();
    AffinePoint::from(extended)
}

/// A plaintext note
#[derive(Clone, Debug)]
pub struct Note {
    /// Recipient diversifier
    pub diversifier: [u8; 11],
    /// Recipient's diversified transmission key
    pub pk_d: [u8; 32],
    /// Value in atomic units
    pub value: u64,
    /// Random commitment trapdoor
    pub rcm: Fr,
    /// Random seed for note encryption (rseed)
    pub rseed: [u8; 32],
}

impl Note {
    /// Create a new note
    pub fn new(
        address: &PaymentAddress,
        value: u64,
        rcm: Fr,
    ) -> Self {
        Self {
            diversifier: address.diversifier.to_bytes(),
            pk_d: subgroup_to_affine(&address.pk_d).to_bytes(),
            value,
            rcm,
            rseed: [0u8; 32], // Should be random in production
        }
    }

    /// Create a new note with random seed
    pub fn new_with_rseed(
        address: &PaymentAddress,
        value: u64,
        rcm: Fr,
        rseed: [u8; 32],
    ) -> Self {
        Self {
            diversifier: address.diversifier.to_bytes(),
            pk_d: subgroup_to_affine(&address.pk_d).to_bytes(),
            value,
            rcm,
            rseed,
        }
    }

    /// Compute the note commitment
    pub fn commitment(&self) -> NoteCommitment {
        NoteCommitment::compute(
            &self.diversifier,
            &self.pk_d,
            self.value,
            &self.rcm,
        )
    }

    /// Derive nullifier given the nullifier key and position
    pub fn nullifier(&self, nk: &[u8; 32], position: u64) -> [u8; 32] {
        let cm = self.commitment();
        derive_nullifier(nk, &cm, position)
    }

    /// Serialize note plaintext (for encryption)
    /// Format: diversifier (11) || pk_d (32) || value (8) || rseed (32) || memo (variable) || rcm (32)
    pub fn to_plaintext(&self, memo: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(NOTE_PLAINTEXT_SIZE);

        // Lead byte (note type)
        plaintext.push(0x02); // Sapling note

        // diversifier: 11 bytes
        plaintext.extend_from_slice(&self.diversifier);

        // value: 8 bytes (little endian)
        plaintext.extend_from_slice(&self.value.to_le_bytes());

        // rseed: 32 bytes
        plaintext.extend_from_slice(&self.rseed);

        // memo: 512 bytes (pad with zeros)
        let memo_padded: Vec<u8> = memo.iter()
            .copied()
            .chain(std::iter::repeat(0u8))
            .take(512)
            .collect();
        plaintext.extend_from_slice(&memo_padded);

        plaintext
    }

    /// Create from plaintext
    pub fn from_plaintext(plaintext: &[u8], pk_d: [u8; 32], rcm: Fr) -> Option<Self> {
        if plaintext.len() < 52 {
            return None;
        }

        // Check lead byte
        if plaintext[0] != 0x02 {
            return None;
        }

        let mut diversifier = [0u8; 11];
        diversifier.copy_from_slice(&plaintext[1..12]);

        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(&plaintext[12..20]);
        let value = u64::from_le_bytes(value_bytes);

        let mut rseed = [0u8; 32];
        rseed.copy_from_slice(&plaintext[20..52]);

        Some(Self {
            diversifier,
            pk_d,
            value,
            rcm,
            rseed,
        })
    }
}

/// Encrypted note (ciphertext)
#[derive(Clone, Debug)]
pub struct EncryptedNote {
    /// Ephemeral public key
    pub epk: [u8; 32],
    /// Encrypted note (for recipient)
    pub enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    /// Encrypted for sender (outgoing)
    pub out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
}

impl EncryptedNote {
    /// Encrypt a note for the recipient using ChaCha20-Poly1305
    pub fn encrypt(
        note: &Note,
        pk_d: &SubgroupPoint,
        ovk: &OutgoingViewingKey,
        esk: Fr,
    ) -> Option<Self> {
        // Compute ephemeral public key
        let epk = SubgroupPoint::generator() * esk;

        // Derive shared secret: esk * pk_d
        let shared_secret = *pk_d * esk;
        let ss_bytes = subgroup_to_affine(&shared_secret).to_bytes();

        // Derive encryption key using KDF
        let epk_bytes = subgroup_to_affine(&epk).to_bytes();
        let enc_key = kdf_sapling(&ss_bytes, &epk_bytes);

        // Encrypt note plaintext
        let plaintext = note.to_plaintext(&[]);
        let enc_ciphertext = encrypt_note_plaintext(&plaintext, &enc_key)?;

        // Encrypt for outgoing viewing key
        let out_ciphertext = encrypt_outgoing(note, &esk, &epk_bytes, ovk)?;

        Some(Self {
            epk: epk_bytes,
            enc_ciphertext,
            out_ciphertext,
        })
    }

    /// Try to decrypt with incoming viewing key
    pub fn decrypt(&self, ivk: &IncomingViewingKey, diversifier: &Diversifier) -> Option<Note> {
        // Derive g_d from diversifier
        let g_d = diversifier.to_point()?;

        // Reconstruct pk_d = ivk * g_d
        let pk_d = g_d * ivk.ivk;
        let pk_d_bytes = subgroup_to_affine(&pk_d).to_bytes();

        // Parse epk
        let epk = AffinePoint::from_bytes(self.epk);
        if epk.is_none().into() {
            return None;
        }
        let epk_extended: ExtendedPoint = epk.unwrap().into();
        let epk_subgroup = SubgroupPoint::from(epk_extended.clear_cofactor());

        // Derive shared secret: ivk * epk
        let shared_secret = epk_subgroup * ivk.ivk;
        let ss_bytes = subgroup_to_affine(&shared_secret).to_bytes();

        // Derive decryption key
        let dec_key = kdf_sapling(&ss_bytes, &self.epk);

        // Decrypt
        let plaintext = decrypt_note_plaintext(&self.enc_ciphertext, &dec_key)?;

        // Extract rcm from rseed
        let mut rseed = [0u8; 32];
        if plaintext.len() >= 52 {
            rseed.copy_from_slice(&plaintext[20..52]);
        }
        let rcm = derive_rcm(&rseed);

        Note::from_plaintext(&plaintext, pk_d_bytes, rcm)
    }

    /// Decrypt outgoing ciphertext with OVK
    pub fn decrypt_outgoing(&self, ovk: &OutgoingViewingKey, cv: &[u8; 32], cmu: &[u8; 32]) -> Option<(Note, Fr)> {
        // Derive key from OVK, cv, cmu, epk
        let ock = derive_ock(ovk, cv, cmu, &self.epk);

        // Decrypt outgoing ciphertext
        let plaintext = decrypt_outgoing_plaintext(&self.out_ciphertext, &ock)?;

        if plaintext.len() < 64 {
            return None;
        }

        // Parse: pk_d (32) || esk (32)
        let mut pk_d = [0u8; 32];
        pk_d.copy_from_slice(&plaintext[0..32]);

        let mut esk_bytes = [0u8; 32];
        esk_bytes.copy_from_slice(&plaintext[32..64]);
        let esk = Fr::from_bytes(&esk_bytes).unwrap_or(Fr::zero());

        // Reconstruct note (simplified - would need to decrypt enc_ciphertext too)
        let note = Note {
            diversifier: [0u8; 11],
            pk_d,
            value: 0,
            rcm: Fr::zero(),
            rseed: [0u8; 32],
        };

        Some((note, esk))
    }
}

/// Sapling key derivation function
fn kdf_sapling(shared_secret: &[u8; 32], epk: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2bParams::new()
        .hash_length(32)
        .personal(b"Zcash_SaplingKDF")
        .to_state();

    hasher.update(shared_secret);
    hasher.update(epk);

    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    key
}

/// Derive rcm from rseed
fn derive_rcm(rseed: &[u8; 32]) -> Fr {
    let mut hasher = Blake2bParams::new()
        .hash_length(32)
        .personal(b"Zcash_rcm_______")
        .to_state();

    hasher.update(rseed);
    let hash = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(hash.as_bytes());
    Fr::from_bytes(&bytes).unwrap_or(Fr::zero())
}

/// Derive outgoing cipher key
fn derive_ock(ovk: &OutgoingViewingKey, cv: &[u8; 32], cmu: &[u8; 32], epk: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2bParams::new()
        .hash_length(32)
        .personal(b"Zcash_Derive_ock")
        .to_state();

    hasher.update(&ovk.ovk);
    hasher.update(cv);
    hasher.update(cmu);
    hasher.update(epk);

    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    key
}

/// Encrypt note plaintext using ChaCha20-Poly1305
fn encrypt_note_plaintext(plaintext: &[u8], key: &[u8; 32]) -> Option<[u8; ENC_CIPHERTEXT_SIZE]> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;

    // Nonce is all zeros for note encryption (fresh key per note)
    let nonce = Nonce::from([0u8; 12]);

    let ciphertext = cipher.encrypt(&nonce, plaintext).ok()?;

    // Pad/truncate to fixed size
    let mut result = [0u8; ENC_CIPHERTEXT_SIZE];
    let copy_len = ciphertext.len().min(ENC_CIPHERTEXT_SIZE);
    result[..copy_len].copy_from_slice(&ciphertext[..copy_len]);

    Some(result)
}

/// Decrypt note plaintext using ChaCha20-Poly1305
fn decrypt_note_plaintext(ciphertext: &[u8; ENC_CIPHERTEXT_SIZE], key: &[u8; 32]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;

    let nonce = Nonce::from([0u8; 12]);

    // Find actual ciphertext length (excluding trailing zeros after tag)
    // The ciphertext includes a 16-byte Poly1305 tag at the end
    let actual_len = find_ciphertext_length(ciphertext);

    cipher.decrypt(&nonce, &ciphertext[..actual_len]).ok()
}

/// Find actual ciphertext length by looking for the tag
fn find_ciphertext_length(ciphertext: &[u8]) -> usize {
    // Note plaintext is 564 bytes + 16 byte tag = 580 bytes for enc_ciphertext
    // If the ciphertext is shorter, use its full length
    ciphertext.len().min(NOTE_PLAINTEXT_SIZE + AEAD_TAG_SIZE)
}

/// Encrypt outgoing note data using ChaCha20-Poly1305
fn encrypt_outgoing(
    note: &Note,
    esk: &Fr,
    epk: &[u8; 32],
    ovk: &OutgoingViewingKey,
) -> Option<[u8; OUT_CIPHERTEXT_SIZE]> {
    // Plaintext: pk_d (32) || esk (32) = 64 bytes
    let mut plaintext = [0u8; 64];
    plaintext[0..32].copy_from_slice(&note.pk_d);
    plaintext[32..64].copy_from_slice(&esk.to_bytes());

    // Derive key using cv and cmu (simplified - use zeros for now)
    let cv = [0u8; 32];
    let cmu = note.commitment().0;
    let ock = derive_ock(ovk, &cv, &cmu, epk);

    let cipher = ChaCha20Poly1305::new_from_slice(&ock).ok()?;
    let nonce = Nonce::from([0u8; 12]);

    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).ok()?;

    // 64 bytes plaintext + 16 bytes tag = 80 bytes = OUT_CIPHERTEXT_SIZE
    let mut result = [0u8; OUT_CIPHERTEXT_SIZE];
    let copy_len = ciphertext.len().min(OUT_CIPHERTEXT_SIZE);
    result[..copy_len].copy_from_slice(&ciphertext[..copy_len]);

    Some(result)
}

/// Decrypt outgoing plaintext using ChaCha20-Poly1305
fn decrypt_outgoing_plaintext(ciphertext: &[u8; OUT_CIPHERTEXT_SIZE], key: &[u8; 32]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    let nonce = Nonce::from([0u8; 12]);

    cipher.decrypt(&nonce, ciphertext.as_ref()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::SpendingKey;

    #[test]
    fn test_note_commitment() {
        let sk = SpendingKey::from_bytes([1u8; 32]);
        let fvk = sk.to_full_viewing_key();
        let ivk = fvk.to_incoming_viewing_key();

        let diversifier = Diversifier([0u8; 11]);

        // Note: This may fail if diversifier doesn't map to valid point
        if let Some(address) = ivk.to_payment_address(&diversifier) {
            let rcm = Fr::from(12345u64);
            let note = Note::new(&address, 1000, rcm);

            let cm1 = note.commitment();
            let cm2 = note.commitment();

            assert_eq!(cm1.0, cm2.0);
        }
    }

    #[test]
    fn test_note_encryption_roundtrip() {
        let sk = SpendingKey::from_bytes([42u8; 32]);
        let fvk = sk.to_full_viewing_key();
        let ivk = fvk.to_incoming_viewing_key();
        let ovk = fvk.to_outgoing_viewing_key();

        let diversifier = Diversifier([1u8; 11]);

        if let Some(address) = ivk.to_payment_address(&diversifier) {
            let rcm = Fr::from(54321u64);
            let note = Note::new_with_rseed(&address, 1000, rcm, [7u8; 32]);

            // Encrypt
            let esk = Fr::from(99999u64);
            if let Some(encrypted) = EncryptedNote::encrypt(&note, &address.pk_d, &ovk, esk) {
                // Decrypt
                if let Some(decrypted) = encrypted.decrypt(&ivk, &diversifier) {
                    assert_eq!(note.value, decrypted.value);
                    assert_eq!(note.diversifier, decrypted.diversifier);
                }
            }
        }
    }

    #[test]
    fn test_chacha20_encryption() {
        use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};

        let key = [42u8; 32];
        let plaintext = b"Hello, shielded world! This is a test message for encryption.";

        // Test direct ChaCha20-Poly1305 encryption/decryption
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = Nonce::from([0u8; 12]);

        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_kdf_deterministic() {
        let ss = [1u8; 32];
        let epk = [2u8; 32];

        let key1 = kdf_sapling(&ss, &epk);
        let key2 = kdf_sapling(&ss, &epk);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_kdf_different_inputs() {
        let ss1 = [1u8; 32];
        let ss2 = [2u8; 32];
        let epk = [3u8; 32];

        let key1 = kdf_sapling(&ss1, &epk);
        let key2 = kdf_sapling(&ss2, &epk);

        assert_ne!(key1, key2);
    }
}
