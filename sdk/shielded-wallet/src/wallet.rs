//! Shielded wallet for YaCoin
//!
//! Manages shielded notes, tracks balances, and creates transactions.

use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use jubjub::Fr;
use blake2b_simd::Params as Blake2bParams;

use crate::keys::{SpendingKey, FullViewingKey, IncomingViewingKey, OutgoingViewingKey, PaymentAddress, Diversifier};
use crate::note::{Note, EncryptedNote};
use crate::prover::{ShieldedProver, SpendProof, OutputProof, MerkleWitness};
use crate::error::WalletError;

/// Derive esk from rseed using Sapling PRF expansion
/// This matches Sapling's derivation: esk = PRF_expand(rseed, 0x05)
fn derive_esk_from_rseed(rseed: &[u8; 32]) -> Fr {
    let mut hasher = Blake2bParams::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .to_state();

    hasher.update(rseed);
    hasher.update(&[0x05]); // SAPLING_ESK domain separator

    let hash = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hash.as_bytes());
    Fr::from_bytes_wide(&bytes)
}

/// A tracked shielded note with metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrackedNote {
    /// The decrypted note
    pub note: Note,
    /// Position in the commitment tree
    pub position: u64,
    /// Note commitment
    pub commitment: [u8; 32],
    /// Whether the note has been spent
    pub spent: bool,
    /// Block height when received
    pub received_height: u64,
    /// Transaction hash
    pub txid: [u8; 32],
}

/// Shielded balance summary
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShieldedBalance {
    /// Total confirmed balance (spendable)
    pub confirmed: u64,
    /// Pending incoming (unconfirmed)
    pub pending_incoming: u64,
    /// Pending outgoing (unconfirmed spends)
    pub pending_outgoing: u64,
    /// Number of unspent notes
    pub note_count: usize,
}

impl ShieldedBalance {
    /// Available balance (confirmed - pending outgoing)
    pub fn available(&self) -> u64 {
        self.confirmed.saturating_sub(self.pending_outgoing)
    }
}

/// Shielded wallet state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletState {
    /// Spending key (encrypted in production)
    spending_key: [u8; 32],
    /// All tracked notes
    notes: Vec<TrackedNote>,
    /// Default diversifier index
    diversifier_index: u64,
    /// Known nullifiers (to detect spent notes)
    known_nullifiers: HashMap<[u8; 32], u64>, // nullifier -> note position
    /// Last scanned block height
    pub last_scanned_height: u64,
}

impl Default for WalletState {
    fn default() -> Self {
        Self {
            spending_key: [0u8; 32],
            notes: Vec::new(),
            diversifier_index: 0,
            known_nullifiers: HashMap::new(),
            last_scanned_height: 0,
        }
    }
}

/// Main shielded wallet
pub struct ShieldedWallet {
    /// Wallet state
    state: WalletState,
    /// Prover for generating proofs
    prover: ShieldedProver,
    /// Full viewing key (derived from spending key)
    fvk: FullViewingKey,
    /// Path to wallet file
    wallet_path: Option<PathBuf>,
}

impl ShieldedWallet {
    /// Create a new wallet from a spending key
    pub fn new(sk: SpendingKey) -> Result<Self, WalletError> {
        let fvk = sk.to_full_viewing_key();
        let prover = ShieldedProver::new()?;

        Ok(Self {
            state: WalletState {
                spending_key: sk.to_bytes(),
                ..Default::default()
            },
            prover,
            fvk,
            wallet_path: None,
        })
    }

    /// Create from seed phrase
    pub fn from_seed(seed: &[u8]) -> Result<Self, WalletError> {
        let sk = SpendingKey::from_seed(seed);
        Self::new(sk)
    }

    /// Load wallet from file
    pub fn load(path: &PathBuf) -> Result<Self, WalletError> {
        let data = std::fs::read(path)?;
        let state: WalletState = serde_json::from_slice(&data)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        let sk = SpendingKey::from_bytes(state.spending_key);
        let fvk = sk.to_full_viewing_key();
        let prover = ShieldedProver::new()?;

        Ok(Self {
            state,
            prover,
            fvk,
            wallet_path: Some(path.clone()),
        })
    }

    /// Save wallet to file
    pub fn save(&self, path: &PathBuf) -> Result<(), WalletError> {
        let data = serde_json::to_vec_pretty(&self.state)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        std::fs::write(path, data)?;
        Ok(())
    }

    /// Get the default payment address
    pub fn default_address(&self) -> Result<PaymentAddress, WalletError> {
        self.fvk.default_address()
    }

    /// Generate a new payment address
    pub fn new_address(&mut self) -> Result<PaymentAddress, WalletError> {
        let ivk = self.fvk.to_incoming_viewing_key();

        // Find next valid diversifier
        loop {
            self.state.diversifier_index += 1;
            let mut d = [0u8; 11];
            d[..8].copy_from_slice(&self.state.diversifier_index.to_le_bytes());

            let diversifier = Diversifier(d);
            if let Some(address) = ivk.to_payment_address(&diversifier) {
                return Ok(address);
            }

            if self.state.diversifier_index > 1_000_000 {
                return Err(WalletError::InvalidDiversifier);
            }
        }
    }

    /// Get the full viewing key
    pub fn full_viewing_key(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// Get incoming viewing key
    pub fn incoming_viewing_key(&self) -> IncomingViewingKey {
        self.fvk.to_incoming_viewing_key()
    }

    /// Get outgoing viewing key
    pub fn outgoing_viewing_key(&self) -> OutgoingViewingKey {
        self.fvk.to_outgoing_viewing_key()
    }

    /// Get current balance
    pub fn balance(&self) -> ShieldedBalance {
        let mut balance = ShieldedBalance::default();

        for note in &self.state.notes {
            if !note.spent {
                balance.confirmed += note.note.value;
                balance.note_count += 1;
            }
        }

        balance
    }

    /// Scan encrypted notes for ones addressed to us
    pub fn scan_notes(
        &mut self,
        encrypted_notes: &[(EncryptedNote, u64, [u8; 32])], // (note, position, txid)
        block_height: u64,
    ) -> Vec<TrackedNote> {
        let ivk = self.fvk.to_incoming_viewing_key();
        let mut found = Vec::new();

        for (enc_note, position, txid) in encrypted_notes {
            // Try each diversifier we've used
            for idx in 0..=self.state.diversifier_index.max(10) {
                let mut d = [0u8; 11];
                d[..8].copy_from_slice(&idx.to_le_bytes());
                let diversifier = Diversifier(d);

                if let Some(note) = enc_note.decrypt(&ivk, &diversifier) {
                    let cm = note.commitment();

                    let tracked = TrackedNote {
                        note,
                        position: *position,
                        commitment: cm.0,
                        spent: false,
                        received_height: block_height,
                        txid: *txid,
                    };

                    found.push(tracked.clone());
                    self.state.notes.push(tracked);
                    break;
                }
            }
        }

        self.state.last_scanned_height = block_height;
        found
    }

    /// Mark notes as spent based on nullifiers
    pub fn mark_spent(&mut self, nullifiers: &[[u8; 32]]) {
        let nk = self.fvk.nk_bytes();

        for tracked in &mut self.state.notes {
            if tracked.spent {
                continue;
            }

            let nullifier = tracked.note.nullifier(&nk, tracked.position);

            if nullifiers.contains(&nullifier) {
                tracked.spent = true;
            }
        }
    }

    /// Select notes for spending a given amount
    pub fn select_notes(&self, amount: u64) -> Result<Vec<&TrackedNote>, WalletError> {
        let mut selected = Vec::new();
        let mut total = 0u64;

        // Simple greedy selection - pick notes until we have enough
        for note in &self.state.notes {
            if note.spent {
                continue;
            }

            selected.push(note);
            total += note.note.value;

            if total >= amount {
                return Ok(selected);
            }
        }

        Err(WalletError::InsufficientBalance {
            have: total,
            need: amount,
        })
    }

    /// Create a spend proof for a note
    pub fn create_spend_proof(
        &mut self,
        note: &TrackedNote,
        witness: &MerkleWitness,
        anchor: [u8; 32],
    ) -> Result<SpendProof, WalletError> {
        let sk = SpendingKey::from_bytes(self.state.spending_key);

        // Generate random value commitment blinding factor
        let mut rcv_bytes = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rcv_bytes);
        let rcv = Fr::from_bytes_wide(&rcv_bytes);

        self.prover.create_spend_proof(&sk, &note.note, witness, anchor, rcv)
    }

    /// Create an output proof for a new note
    pub fn create_output_proof(
        &mut self,
        recipient: &PaymentAddress,
        amount: u64,
    ) -> Result<(OutputProof, Note, EncryptedNote), WalletError> {
        // Create the note
        let note = Note::new(recipient, amount);

        // Generate random blinding factor for value commitment
        let mut rng = rand::thread_rng();
        let mut rcv_bytes = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rng, &mut rcv_bytes);
        let rcv = Fr::from_bytes_wide(&rcv_bytes);

        // Derive esk from rseed (same derivation as Sapling)
        // esk = PRF_expand(rseed, 0x05) for AfterZip212
        let esk = derive_esk_from_rseed(&note.rseed);

        // Create output proof (internally derives esk from rseed too)
        let proof = self.prover.create_output_proof(&note, rcv)?;

        // Encrypt the note
        let ovk = self.fvk.to_outgoing_viewing_key();
        let encrypted = EncryptedNote::encrypt_with_esk(&note, &recipient.pk_d, &ovk, esk)
            .ok_or(WalletError::InvalidNote)?;

        Ok((proof, note, encrypted))
    }

    /// Get all unspent notes
    pub fn unspent_notes(&self) -> Vec<&TrackedNote> {
        self.state.notes.iter().filter(|n| !n.spent).collect()
    }

    /// Get note count
    pub fn note_count(&self) -> usize {
        self.state.notes.len()
    }

    /// Check if prover has parameters loaded
    pub fn prover_ready(&self) -> bool {
        self.prover.params_available()
    }

    /// Export the incoming viewing key (for watch-only wallets)
    pub fn export_ivk(&self) -> [u8; 32] {
        self.incoming_viewing_key().to_bytes()
    }

    /// Export the outgoing viewing key
    pub fn export_ovk(&self) -> [u8; 32] {
        self.outgoing_viewing_key().to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_creation() {
        let wallet = ShieldedWallet::from_seed(b"test wallet seed").unwrap();
        let address = wallet.default_address().unwrap();

        assert!(address.to_bech32().starts_with("ys1"));
    }

    #[test]
    fn test_balance() {
        let wallet = ShieldedWallet::from_seed(b"test").unwrap();
        let balance = wallet.balance();

        assert_eq!(balance.confirmed, 0);
        assert_eq!(balance.note_count, 0);
    }

    #[test]
    fn test_address_generation() {
        let mut wallet = ShieldedWallet::from_seed(b"test").unwrap();

        let addr1 = wallet.default_address().unwrap();
        let addr2 = wallet.new_address().unwrap();

        // Different addresses
        assert_ne!(addr1.to_bytes(), addr2.to_bytes());
    }

    #[test]
    fn test_wallet_serialization() {
        let wallet = ShieldedWallet::from_seed(b"serialize test").unwrap();

        // Serialize state
        let data = serde_json::to_string(&wallet.state).unwrap();
        let _: WalletState = serde_json::from_str(&data).unwrap();
    }
}
