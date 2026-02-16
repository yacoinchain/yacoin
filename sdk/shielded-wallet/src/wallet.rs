//! Shielded wallet for managing private transactions
//!
//! Provides a high-level interface for creating and managing shielded
//! transactions on the YaCoin blockchain.

use crate::error::{WalletError, WalletResult};
use crate::keys::{ExtendedSpendingKey, ShieldedAddress, ViewingKey};
use crate::transaction::{WalletNote, ShieldBuilder, UnshieldBuilder, ShieldedTransferBuilder};
use yacoin_shielded_transfer::instruction::ShieldedInstruction;
use solana_pubkey::Pubkey;
use solana_instruction::Instruction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The shielded transfer program ID
pub const SHIELDED_PROGRAM_ID: Pubkey = yacoin_shielded_transfer::id::ID;

/// A shielded wallet for managing private transactions
pub struct ShieldedWallet {
    /// The extended spending key
    spending_key: ExtendedSpendingKey,
    /// Cached viewing key
    viewing_key: ViewingKey,
    /// Known notes (owned by this wallet)
    notes: Vec<WalletNote>,
    /// Addresses generated for this wallet
    addresses: Vec<ShieldedAddress>,
    /// Next diversifier index to use
    next_diversifier: u64,
    /// Current anchor (commitment tree root)
    current_anchor: [u8; 32],
}

impl ShieldedWallet {
    /// Create a new wallet from a seed
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let spending_key = ExtendedSpendingKey::from_seed(seed);
        let fvk = spending_key.to_full_viewing_key();
        let viewing_key = ViewingKey::from_full_viewing_key(&fvk);

        Self {
            spending_key,
            viewing_key,
            notes: Vec::new(),
            addresses: Vec::new(),
            next_diversifier: 0,
            current_anchor: [0u8; 32],
        }
    }

    /// Create a new random wallet
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        Self::from_seed(&seed)
    }

    /// Get the default payment address
    pub fn default_address(&mut self) -> WalletResult<ShieldedAddress> {
        if self.addresses.is_empty() {
            let (addr, actual_index) = self.spending_key.get_address_with_index(0)?;
            self.next_diversifier = actual_index + 1; // Start next search after this one
            self.addresses.push(addr.clone());
            Ok(addr)
        } else {
            Ok(self.addresses[0].clone())
        }
    }

    /// Generate a new unique payment address
    pub fn new_address(&mut self) -> WalletResult<ShieldedAddress> {
        let (addr, actual_index) = self.spending_key.get_address_with_index(self.next_diversifier)?;
        self.next_diversifier = actual_index + 1; // Always advance past the index we just used
        self.addresses.push(addr.clone());
        Ok(addr)
    }

    /// Get the viewing key for this wallet
    pub fn viewing_key(&self) -> &ViewingKey {
        &self.viewing_key
    }

    /// Update the current anchor (merkle root)
    pub fn set_anchor(&mut self, anchor: [u8; 32]) {
        self.current_anchor = anchor;
    }

    /// Get the total shielded balance
    pub fn balance(&self) -> u64 {
        self.notes.iter()
            .filter(|n| !n.spent)
            .map(|n| n.value())
            .sum()
    }

    /// Get spendable balance (notes with witnesses)
    pub fn spendable_balance(&self) -> u64 {
        self.notes.iter()
            .filter(|n| n.is_spendable())
            .map(|n| n.value())
            .sum()
    }

    /// Add a note to the wallet
    pub fn add_note(&mut self, note: WalletNote) {
        self.notes.push(note);
    }

    /// Mark a note as spent by its nullifier
    pub fn mark_spent(&mut self, nullifier: &[u8; 32]) {
        for note in &mut self.notes {
            if &note.nullifier == nullifier {
                note.spent = true;
                break;
            }
        }
    }

    /// Update witness paths for all notes
    pub fn update_witnesses(&mut self, witnesses: HashMap<u64, Vec<[u8; 32]>>) {
        for note in &mut self.notes {
            if let Some(path) = witnesses.get(&note.position) {
                note.witness_path = Some(path.clone());
            }
        }
    }

    /// Select notes to spend for a given amount
    fn select_notes(&self, amount: u64) -> WalletResult<Vec<&WalletNote>> {
        let mut selected = Vec::new();
        let mut total = 0u64;

        // Simple greedy selection - pick largest spendable notes first
        let mut spendable: Vec<_> = self.notes.iter()
            .filter(|n| n.is_spendable())
            .collect();
        spendable.sort_by(|a, b| b.value().cmp(&a.value()));

        for note in spendable {
            if total >= amount {
                break;
            }
            selected.push(note);
            total += note.value();
        }

        if total < amount {
            return Err(WalletError::InsufficientFunds);
        }

        Ok(selected)
    }

    /// Create a shield instruction (transparent -> shielded)
    pub fn create_shield_instruction(
        &mut self,
        amount: u64,
        from_token_account: Pubkey,
        pool_account: Pubkey,
    ) -> WalletResult<Instruction> {
        let to_address = self.default_address()?;
        let builder = ShieldBuilder::new(amount, to_address);
        let output = builder.build()?;

        let instruction_data = ShieldedInstruction::Shield {
            amount,
            output,
        };

        let data = borsh::to_vec(&instruction_data)
            .map_err(|_| WalletError::SerializationError)?;

        Ok(Instruction {
            program_id: SHIELDED_PROGRAM_ID,
            accounts: vec![
                solana_instruction::AccountMeta::new(from_token_account, true),
                solana_instruction::AccountMeta::new(pool_account, false),
            ],
            data,
        })
    }

    /// Create an unshield instruction (shielded -> transparent)
    pub fn create_unshield_instruction(
        &self,
        amount: u64,
        to_token_account: Pubkey,
        pool_account: Pubkey,
    ) -> WalletResult<Instruction> {
        // Select a note to spend
        let notes = self.select_notes(amount)?;
        if notes.is_empty() {
            return Err(WalletError::InsufficientFunds);
        }

        // For simplicity, use the first selected note
        let note = notes[0].clone();

        let builder = UnshieldBuilder::new(
            amount,
            note,
            self.spending_key.clone(),
            self.current_anchor,
        )?;
        let spend = builder.build()?;

        let instruction_data = ShieldedInstruction::Unshield {
            amount,
            spend,
            recipient: to_token_account.to_bytes(),
        };

        let data = borsh::to_vec(&instruction_data)
            .map_err(|_| WalletError::SerializationError)?;

        Ok(Instruction {
            program_id: SHIELDED_PROGRAM_ID,
            accounts: vec![
                solana_instruction::AccountMeta::new(pool_account, false),
                solana_instruction::AccountMeta::new(to_token_account, false),
            ],
            data,
        })
    }

    /// Create a shielded transfer instruction (shielded -> shielded)
    pub fn create_transfer_instruction(
        &self,
        amount: u64,
        to_address: ShieldedAddress,
        pool_account: Pubkey,
    ) -> WalletResult<Instruction> {
        let selected_notes = self.select_notes(amount)?;
        let total_in: u64 = selected_notes.iter().map(|n| n.value()).sum();

        let mut builder = ShieldedTransferBuilder::new(self.current_anchor);

        // Add spends
        for note in selected_notes {
            builder.add_spend(note.clone(), self.spending_key.clone())?;
        }

        // Add output to recipient
        builder.add_output(amount, to_address);

        // Add change output if needed
        let change = total_in - amount;
        if change > 0 {
            let change_address = self.addresses.first()
                .cloned()
                .ok_or(WalletError::InvalidAddress)?;
            builder.add_output(change, change_address);
        }

        let (spends, outputs, binding_sig) = builder.build()?;

        let instruction_data = ShieldedInstruction::ShieldedTransfer {
            spends,
            outputs,
            binding_sig,
        };

        let data = borsh::to_vec(&instruction_data)
            .map_err(|_| WalletError::SerializationError)?;

        Ok(Instruction {
            program_id: SHIELDED_PROGRAM_ID,
            accounts: vec![
                solana_instruction::AccountMeta::new(pool_account, false),
            ],
            data,
        })
    }

    /// Export viewing key for watch-only access
    pub fn export_viewing_key(&self) -> ViewingKeyExport {
        ViewingKeyExport {
            ivk: self.viewing_key.ivk_bytes(),
            ovk: self.viewing_key.ovk_bytes(),
        }
    }

    /// Export wallet backup (encrypted)
    pub fn export_encrypted(&self, password: &str) -> WalletResult<WalletBackup> {
        use blake2b_simd::Params;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
        use chacha20poly1305::aead::generic_array::GenericArray;

        // Derive encryption key from password
        let key_hash = Params::new()
            .hash_length(32)
            .personal(b"YaCoin_WalletKey")
            .to_state()
            .update(password.as_bytes())
            .finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(key_hash.as_bytes());

        // Serialize spending key
        let sk_bytes = self.spending_key.spending_key.to_bytes();
        let chain_code = self.spending_key.chain_code;

        let mut plaintext = Vec::with_capacity(64);
        plaintext.extend_from_slice(&sk_bytes);
        plaintext.extend_from_slice(&chain_code);

        // Encrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| WalletError::EncryptionError)?;
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        let nonce = GenericArray::from(nonce_bytes);

        let ciphertext = cipher.encrypt(&nonce, plaintext.as_slice())
            .map_err(|_| WalletError::EncryptionError)?;

        Ok(WalletBackup {
            version: 1,
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Import wallet from encrypted backup
    pub fn import_encrypted(backup: &WalletBackup, password: &str) -> WalletResult<Self> {
        use blake2b_simd::Params;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
        use chacha20poly1305::aead::generic_array::GenericArray;

        if backup.version != 1 {
            return Err(WalletError::InvalidBackup);
        }

        // Derive key
        let key_hash = Params::new()
            .hash_length(32)
            .personal(b"YaCoin_WalletKey")
            .to_state()
            .update(password.as_bytes())
            .finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(key_hash.as_bytes());

        // Decrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| WalletError::DecryptionError)?;
        let nonce = GenericArray::from(backup.nonce);

        let plaintext = cipher.decrypt(&nonce, backup.ciphertext.as_slice())
            .map_err(|_| WalletError::DecryptionError)?;

        if plaintext.len() != 64 {
            return Err(WalletError::InvalidBackup);
        }

        let mut sk_bytes = [0u8; 32];
        let mut chain_code = [0u8; 32];
        sk_bytes.copy_from_slice(&plaintext[0..32]);
        chain_code.copy_from_slice(&plaintext[32..64]);

        let spending_key = ExtendedSpendingKey {
            spending_key: yacoin_shielded_transfer::crypto::keys::SpendingKey::from_bytes(sk_bytes),
            chain_code,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_index: 0,
        };

        let fvk = spending_key.to_full_viewing_key();
        let viewing_key = ViewingKey::from_full_viewing_key(&fvk);

        Ok(Self {
            spending_key,
            viewing_key,
            notes: Vec::new(),
            addresses: Vec::new(),
            next_diversifier: 0,
            current_anchor: [0u8; 32],
        })
    }
}

/// Exported viewing key for watch-only wallets
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewingKeyExport {
    pub ivk: [u8; 32],
    pub ovk: [u8; 32],
}

/// Encrypted wallet backup
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletBackup {
    pub version: u8,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Watch-only wallet using just viewing keys
pub struct WatchOnlyWallet {
    viewing_key: ViewingKey,
    notes: Vec<WalletNote>,
    addresses: Vec<ShieldedAddress>,
}

impl WatchOnlyWallet {
    /// Create from exported viewing key
    pub fn from_viewing_key(export: ViewingKeyExport) -> Self {
        use yacoin_shielded_transfer::crypto::keys::{IncomingViewingKey, OutgoingViewingKey};
        use jubjub::Fr;
        use ff::Field;

        let ivk = IncomingViewingKey {
            ivk: Fr::from_bytes(&export.ivk).unwrap_or_else(|| Fr::ZERO),
        };
        let ovk = OutgoingViewingKey { ovk: export.ovk };

        Self {
            viewing_key: ViewingKey { ivk, ovk },
            notes: Vec::new(),
            addresses: Vec::new(),
        }
    }

    /// Get the balance of watched notes
    pub fn balance(&self) -> u64 {
        self.notes.iter()
            .filter(|n| !n.spent)
            .map(|n| n.value())
            .sum()
    }

    /// Add a decrypted note
    pub fn add_note(&mut self, note: WalletNote) {
        self.notes.push(note);
    }

    /// Mark note as spent
    pub fn mark_spent(&mut self, nullifier: &[u8; 32]) {
        for note in &mut self.notes {
            if &note.nullifier == nullifier {
                note.spent = true;
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_creation() {
        let seed = [42u8; 32];
        let wallet = ShieldedWallet::from_seed(&seed);
        assert_eq!(wallet.balance(), 0);
    }

    #[test]
    fn test_address_generation() {
        let seed = [1u8; 32];
        let mut wallet = ShieldedWallet::from_seed(&seed);

        let addr1 = wallet.default_address().unwrap();
        let addr2 = wallet.new_address().unwrap();

        // Addresses should be different due to different diversifiers
        assert_ne!(addr1.diversifier, addr2.diversifier);
    }

    #[test]
    fn test_wallet_backup_restore() {
        let seed = [99u8; 32];
        let wallet = ShieldedWallet::from_seed(&seed);

        let backup = wallet.export_encrypted("password123").unwrap();
        let restored = ShieldedWallet::import_encrypted(&backup, "password123").unwrap();

        // Check keys match
        let orig_fvk = wallet.spending_key.to_full_viewing_key();
        let rest_fvk = restored.spending_key.to_full_viewing_key();
        assert_eq!(orig_fvk.ak_bytes(), rest_fvk.ak_bytes());
    }

    #[test]
    fn test_wrong_password() {
        let seed = [77u8; 32];
        let wallet = ShieldedWallet::from_seed(&seed);

        let backup = wallet.export_encrypted("correct").unwrap();
        let result = ShieldedWallet::import_encrypted(&backup, "wrong");

        assert!(result.is_err());
    }

    #[test]
    fn test_viewing_key_export() {
        let seed = [55u8; 32];
        let wallet = ShieldedWallet::from_seed(&seed);

        let export = wallet.export_viewing_key();

        // Can create watch-only wallet
        let watch = WatchOnlyWallet::from_viewing_key(export);
        assert_eq!(watch.balance(), 0);
    }
}
