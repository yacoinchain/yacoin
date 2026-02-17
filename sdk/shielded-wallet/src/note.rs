//! Note structure and encryption for YaCoin shielded transactions
//!
//! A note represents a shielded value that can only be spent by
//! the holder of the spending key.
//!
//! Uses ChaCha20-Poly1305 AEAD for authenticated encryption.

use jubjub::{Fr, SubgroupPoint, ExtendedPoint, AffinePoint};
use group::cofactor::CofactorGroup;
use blake2b_simd::Params as Blake2bParams;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, Bytes};

use crate::keys::{PaymentAddress, OutgoingViewingKey, IncomingViewingKey, Diversifier};
use crate::commitment::{NoteCommitment, derive_nullifier};
use crate::{ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE};

/// Note plaintext size (without AEAD tag)
const NOTE_PLAINTEXT_SIZE: usize = 564;

/// Helper to convert SubgroupPoint to AffinePoint
fn subgroup_to_affine(point: &SubgroupPoint) -> AffinePoint {
    let extended: ExtendedPoint = (*point).into();
    AffinePoint::from(extended)
}

/// A plaintext note (unencrypted)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Note {
    /// Recipient diversifier
    pub diversifier: [u8; 11],
    /// Recipient's diversified transmission key
    pub pk_d: [u8; 32],
    /// Value in atomic units (lamports for YaCoin)
    pub value: u64,
    /// Random commitment trapdoor
    #[serde(with = "fr_serde")]
    pub rcm: Fr,
    /// Random seed for note encryption
    pub rseed: [u8; 32],
}

// Serde helpers for Fr
mod fr_serde {
    use jubjub::Fr;
    use serde::{Serializer, Deserializer, Deserialize};

    pub fn serialize<S: Serializer>(fr: &Fr, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&fr.to_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Fr, D::Error> {
        let bytes = <[u8; 32]>::deserialize(d)?;
        Fr::from_bytes(&bytes)
            .into_option()
            .ok_or_else(|| serde::de::Error::custom("invalid Fr"))
    }
}

impl Note {
    /// Create a new note for a recipient
    pub fn new(address: &PaymentAddress, value: u64) -> Self {
        let mut rng = rand::thread_rng();
        Self::new_with_rng(address, value, &mut rng)
    }

    /// Create a new note with explicit randomness source
    pub fn new_with_rng<R: RngCore>(address: &PaymentAddress, value: u64, rng: &mut R) -> Self {
        let mut rseed = [0u8; 32];
        rng.fill_bytes(&mut rseed);

        // Derive rcm from rseed
        let rcm = derive_rcm(&rseed);

        Self {
            diversifier: address.diversifier.to_bytes(),
            pk_d: subgroup_to_affine(&address.pk_d).to_bytes(),
            value,
            rcm,
            rseed,
        }
    }

    /// Create note with explicit rcm (for testing)
    pub fn new_with_rcm(address: &PaymentAddress, value: u64, rcm: Fr, rseed: [u8; 32]) -> Self {
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

    /// Derive nullifier given the nullifier key and tree position
    pub fn nullifier(&self, nk: &[u8; 32], position: u64) -> [u8; 32] {
        let cm = self.commitment();
        derive_nullifier(nk, &cm, position)
    }

    /// Serialize to plaintext bytes for encryption
    pub fn to_plaintext(&self, memo: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(NOTE_PLAINTEXT_SIZE);

        // Lead byte (note type)
        plaintext.push(0x02); // Sapling note

        // Diversifier: 11 bytes
        plaintext.extend_from_slice(&self.diversifier);

        // Value: 8 bytes (little endian)
        plaintext.extend_from_slice(&self.value.to_le_bytes());

        // rseed: 32 bytes
        plaintext.extend_from_slice(&self.rseed);

        // Memo: 512 bytes (padded)
        let memo_len = memo.len().min(512);
        plaintext.extend_from_slice(&memo[..memo_len]);
        plaintext.resize(plaintext.len() + (512 - memo_len), 0);

        plaintext
    }

    /// Deserialize from plaintext bytes
    pub fn from_plaintext(plaintext: &[u8], pk_d: [u8; 32]) -> Option<Self> {
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

        let rcm = derive_rcm(&rseed);

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
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedNote {
    /// Ephemeral public key (for ECDH)
    pub epk: [u8; 32],
    /// Encrypted note ciphertext (for recipient)
    #[serde_as(as = "Bytes")]
    pub enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    /// Encrypted outgoing data (for sender)
    #[serde_as(as = "Bytes")]
    pub out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
}

impl EncryptedNote {
    /// Encrypt a note for the recipient
    pub fn encrypt(note: &Note, pk_d: &SubgroupPoint, ovk: &OutgoingViewingKey) -> Option<Self> {
        let mut rng = rand::thread_rng();
        Self::encrypt_with_rng(note, pk_d, ovk, &mut rng)
    }

    /// Encrypt with explicit randomness
    pub fn encrypt_with_rng<R: RngCore>(
        note: &Note,
        pk_d: &SubgroupPoint,
        ovk: &OutgoingViewingKey,
        rng: &mut R,
    ) -> Option<Self> {
        // Generate random ephemeral secret key
        let mut esk_bytes = [0u8; 64];
        rng.fill_bytes(&mut esk_bytes);
        let esk = Fr::from_bytes_wide(&esk_bytes);

        Self::encrypt_with_esk(note, pk_d, ovk, esk)
    }

    /// Encrypt with specific ephemeral secret key
    ///
    /// Sapling ECDH:
    /// - g_d = hash(diversifier) -> curve point
    /// - pk_d = ivk * g_d
    /// - epk = esk * g_d
    /// - Sender: shared_secret = esk * pk_d = esk * ivk * g_d
    /// - Receiver: shared_secret = ivk * epk = ivk * esk * g_d
    pub fn encrypt_with_esk(
        note: &Note,
        pk_d: &SubgroupPoint,
        ovk: &OutgoingViewingKey,
        esk: Fr,
    ) -> Option<Self> {
        // Derive g_d from the note's diversifier
        let diversifier = Diversifier::from_bytes(note.diversifier);
        let g_d = diversifier.to_point()?;

        // Compute ephemeral public key: epk = esk * g_d
        let epk = g_d * esk;

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
    ///
    /// Sapling ECDH decryption:
    /// - Receiver has ivk and sees epk = esk * g_d
    /// - shared_secret = ivk * epk = ivk * esk * g_d
    /// - This equals sender's shared_secret = esk * pk_d = esk * ivk * g_d
    pub fn decrypt(&self, ivk: &IncomingViewingKey, diversifier: &Diversifier) -> Option<Note> {
        // Derive g_d from diversifier
        let g_d = diversifier.to_point()?;

        // Reconstruct pk_d = ivk * g_d
        let pk_d = g_d * ivk.ivk;
        let pk_d_bytes = subgroup_to_affine(&pk_d).to_bytes();

        // Parse epk = esk * g_d
        let epk = AffinePoint::from_bytes(self.epk);
        if epk.is_none().into() {
            return None;
        }
        let epk_extended: ExtendedPoint = epk.unwrap().into();

        // Derive shared secret: ivk * epk = ivk * esk * g_d
        // This equals sender's: esk * pk_d = esk * ivk * g_d
        let shared_secret = epk_extended * ivk.ivk;
        let ss_affine = AffinePoint::from(shared_secret);
        let ss_bytes = ss_affine.to_bytes();

        // Derive decryption key using KDF
        let dec_key = kdf_sapling(&ss_bytes, &self.epk);

        // Decrypt
        let plaintext = decrypt_note_plaintext(&self.enc_ciphertext, &dec_key)?;

        Note::from_plaintext(&plaintext, pk_d_bytes)
    }

    /// Get ephemeral public key as curve point
    pub fn epk_point(&self) -> Option<SubgroupPoint> {
        let point = AffinePoint::from_bytes(self.epk);
        if point.is_some().into() {
            let extended: ExtendedPoint = point.unwrap().into();
            Some(SubgroupPoint::from(extended.clear_cofactor()))
        } else {
            None
        }
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
        .hash_length(64)
        .personal(b"Zcash_rcm_______")
        .to_state();

    hasher.update(rseed);
    let hash = hasher.finalize();

    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hash.as_bytes());
    Fr::from_bytes_wide(&bytes)
}

/// Encrypt note plaintext using ChaCha20-Poly1305
fn encrypt_note_plaintext(plaintext: &[u8], key: &[u8; 32]) -> Option<[u8; ENC_CIPHERTEXT_SIZE]> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    let nonce = Nonce::from([0u8; 12]); // Fresh key per note

    let ciphertext = cipher.encrypt(&nonce, plaintext).ok()?;

    let mut result = [0u8; ENC_CIPHERTEXT_SIZE];
    let copy_len = ciphertext.len().min(ENC_CIPHERTEXT_SIZE);
    result[..copy_len].copy_from_slice(&ciphertext[..copy_len]);

    Some(result)
}

/// Decrypt note plaintext
fn decrypt_note_plaintext(ciphertext: &[u8; ENC_CIPHERTEXT_SIZE], key: &[u8; 32]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    let nonce = Nonce::from([0u8; 12]);

    // Find actual ciphertext length (plaintext + 16 byte tag)
    let actual_len = (NOTE_PLAINTEXT_SIZE + 16).min(ENC_CIPHERTEXT_SIZE);

    cipher.decrypt(&nonce, &ciphertext[..actual_len]).ok()
}

/// Encrypt outgoing note data
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

    // Derive outgoing cipher key
    let cv = [0u8; 32]; // Simplified - would use actual cv
    let cmu = note.commitment().0;
    let ock = derive_ock(ovk, &cv, &cmu, epk);

    let cipher = ChaCha20Poly1305::new_from_slice(&ock).ok()?;
    let nonce = Nonce::from([0u8; 12]);

    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).ok()?;

    // 64 + 16 = 80 bytes
    let mut result = [0u8; OUT_CIPHERTEXT_SIZE];
    let copy_len = ciphertext.len().min(OUT_CIPHERTEXT_SIZE);
    result[..copy_len].copy_from_slice(&ciphertext[..copy_len]);

    Some(result)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendingKey;

    #[test]
    fn test_note_commitment() {
        let sk = SpendingKey::from_seed(b"test");
        let fvk = sk.to_full_viewing_key();
        let address = fvk.default_address().unwrap();

        let note = Note::new(&address, 1000);
        let cm1 = note.commitment();
        let cm2 = note.commitment();

        assert_eq!(cm1, cm2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let sk = SpendingKey::from_seed(b"test encryption");
        let fvk = sk.to_full_viewing_key();
        let ivk = fvk.to_incoming_viewing_key();
        let ovk = fvk.to_outgoing_viewing_key();
        let address = fvk.default_address().unwrap();

        let note = Note::new(&address, 5000);
        let original_value = note.value;

        let encrypted = EncryptedNote::encrypt(&note, &address.pk_d, &ovk).unwrap();
        let decrypted = encrypted.decrypt(&ivk, &address.diversifier).unwrap();

        assert_eq!(decrypted.value, original_value);
    }
}
