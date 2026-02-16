//! RPC extensions for YaCoin shielded transactions
//!
//! This module provides RPC methods for querying shielded state:
//! - getShieldedBalance: Query balance using viewing key
//! - scanNotes: Find notes owned by a viewing key
//! - getCommitmentProof: Get Merkle proof for a commitment
//! - getNullifierStatus: Check if a nullifier has been spent

use crate::{
    commitment_tree::IncrementalMerkleTree,
    nullifier_set::NullifierSet,
    state::ShieldedPoolState,
    NOTE_COMMITMENT_SIZE, NULLIFIER_SIZE,
};

use serde::{Deserialize, Serialize};

/// Request to get shielded balance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetShieldedBalanceRequest {
    /// Incoming viewing key (hex encoded)
    pub ivk: String,
    /// Optional: specific diversifiers to check
    pub diversifiers: Option<Vec<String>>,
}

/// Response with shielded balance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetShieldedBalanceResponse {
    /// Total shielded balance in atomic units
    pub balance: u64,
    /// Number of spendable notes
    pub note_count: u64,
    /// Commitment tree size at time of scan
    pub commitment_tree_size: u64,
}

/// Request to scan for notes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanNotesRequest {
    /// Incoming viewing key (hex encoded)
    pub ivk: String,
    /// Start position in commitment tree
    pub start_position: Option<u64>,
    /// Maximum notes to return
    pub limit: Option<u64>,
}

/// A decrypted note owned by the viewing key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptedNote {
    /// Position in the commitment tree
    pub position: u64,
    /// Note commitment (hex)
    pub commitment: String,
    /// Note value in atomic units
    pub value: u64,
    /// Diversifier (hex)
    pub diversifier: String,
    /// Whether this note has been spent
    pub spent: bool,
    /// Nullifier if spent (hex)
    pub nullifier: Option<String>,
}

/// Response from scanning notes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanNotesResponse {
    /// Decrypted notes owned by the viewing key
    pub notes: Vec<DecryptedNote>,
    /// Last scanned position
    pub last_position: u64,
    /// Whether there are more notes to scan
    pub has_more: bool,
}

/// Request to get commitment proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetCommitmentProofRequest {
    /// Note commitment (hex)
    pub commitment: String,
    /// Position in the tree (if known)
    pub position: Option<u64>,
}

/// Merkle proof for a commitment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentProof {
    /// Position in the tree
    pub position: u64,
    /// Merkle path (array of sibling hashes, hex encoded)
    pub path: Vec<String>,
    /// Current root (anchor)
    pub anchor: String,
    /// Tree depth
    pub depth: u8,
}

/// Response with commitment proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetCommitmentProofResponse {
    /// The proof, if commitment was found
    pub proof: Option<CommitmentProof>,
    /// Error message if not found
    pub error: Option<String>,
}

/// Request to check nullifier status
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetNullifierStatusRequest {
    /// Nullifier to check (hex)
    pub nullifier: String,
}

/// Response with nullifier status
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetNullifierStatusResponse {
    /// Whether the nullifier has been spent
    pub spent: bool,
    /// Slot when the nullifier was recorded (if spent)
    pub spent_slot: Option<u64>,
}

/// Request to get pool state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetShieldedPoolStateRequest {
    /// Optional commitment config
    pub commitment: Option<String>,
}

/// Response with pool state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetShieldedPoolStateResponse {
    /// Total value in the shielded pool
    pub total_shielded: u64,
    /// Number of note commitments
    pub commitment_count: u64,
    /// Number of spent nullifiers
    pub nullifier_count: u64,
    /// Current Merkle root (anchor)
    pub current_anchor: String,
}

/// Shielded RPC service implementation
pub struct ShieldedRpcService {
    /// The commitment tree
    commitment_tree: IncrementalMerkleTree,
    /// The nullifier set
    nullifier_set: NullifierSet,
    /// Pool state
    pool_state: ShieldedPoolState,
}

impl ShieldedRpcService {
    /// Create a new shielded RPC service
    pub fn new(
        commitment_tree: IncrementalMerkleTree,
        nullifier_set: NullifierSet,
        pool_state: ShieldedPoolState,
    ) -> Self {
        Self {
            commitment_tree,
            nullifier_set,
            pool_state,
        }
    }

    /// Get the shielded pool state
    pub fn get_pool_state(&self, _request: GetShieldedPoolStateRequest) -> GetShieldedPoolStateResponse {
        GetShieldedPoolStateResponse {
            total_shielded: self.pool_state.total_shielded,
            commitment_count: self.pool_state.commitment_count,
            nullifier_count: self.pool_state.nullifier_count,
            current_anchor: hex::encode(self.commitment_tree.root()),
        }
    }

    /// Check if a nullifier has been spent
    pub fn get_nullifier_status(&self, request: GetNullifierStatusRequest) -> GetNullifierStatusResponse {
        let nullifier_bytes = match hex::decode(&request.nullifier) {
            Ok(bytes) if bytes.len() == NULLIFIER_SIZE => {
                let mut arr = [0u8; NULLIFIER_SIZE];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                return GetNullifierStatusResponse {
                    spent: false,
                    spent_slot: None,
                };
            }
        };

        GetNullifierStatusResponse {
            spent: self.nullifier_set.contains(&nullifier_bytes),
            spent_slot: None, // TODO: Track spent slot
        }
    }

    /// Get a commitment proof (Merkle witness)
    pub fn get_commitment_proof(&self, request: GetCommitmentProofRequest) -> GetCommitmentProofResponse {
        let commitment_bytes = match hex::decode(&request.commitment) {
            Ok(bytes) if bytes.len() == NOTE_COMMITMENT_SIZE => {
                let mut arr = [0u8; NOTE_COMMITMENT_SIZE];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                return GetCommitmentProofResponse {
                    proof: None,
                    error: Some("Invalid commitment format".to_string()),
                };
            }
        };

        // If position is provided, get the witness
        if let Some(position) = request.position {
            match self.commitment_tree.witness(position) {
                Ok(witness) => {
                    GetCommitmentProofResponse {
                        proof: Some(CommitmentProof {
                            position,
                            path: witness.path.iter().map(|h| hex::encode(h)).collect(),
                            anchor: hex::encode(self.commitment_tree.root()),
                            depth: 32,
                        }),
                        error: None,
                    }
                }
                Err(e) => GetCommitmentProofResponse {
                    proof: None,
                    error: Some(format!("Failed to get witness: {:?}", e)),
                },
            }
        } else {
            // TODO: Search for commitment position
            GetCommitmentProofResponse {
                proof: None,
                error: Some("Position required (commitment search not implemented)".to_string()),
            }
        }
    }

    /// Scan for notes owned by a viewing key
    /// This is a placeholder - real implementation requires decrypting notes
    pub fn scan_notes(&self, request: ScanNotesRequest) -> ScanNotesResponse {
        // Parse IVK
        let _ivk_bytes = match hex::decode(&request.ivk) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            _ => {
                return ScanNotesResponse {
                    notes: vec![],
                    last_position: 0,
                    has_more: false,
                };
            }
        };

        let start = request.start_position.unwrap_or(0);
        let _limit = request.limit.unwrap_or(100);

        // TODO: Implement note scanning
        // This requires:
        // 1. Iterating through encrypted notes in the commitment tree
        // 2. Attempting to decrypt each with the IVK
        // 3. Checking nullifier set for spent notes

        ScanNotesResponse {
            notes: vec![],
            last_position: start,
            has_more: false,
        }
    }

    /// Get shielded balance for a viewing key
    pub fn get_shielded_balance(&self, request: GetShieldedBalanceRequest) -> GetShieldedBalanceResponse {
        // Scan notes and sum unspent values
        let scan_result = self.scan_notes(ScanNotesRequest {
            ivk: request.ivk,
            start_position: None,
            limit: None,
        });

        let balance: u64 = scan_result
            .notes
            .iter()
            .filter(|n| !n.spent)
            .map(|n| n.value)
            .sum();

        let note_count = scan_result.notes.iter().filter(|n| !n.spent).count() as u64;

        GetShieldedBalanceResponse {
            balance,
            note_count,
            commitment_tree_size: self.commitment_tree.size() as u64,
        }
    }
}

/// RPC method names for shielded operations
pub mod methods {
    /// Get shielded pool state
    pub const GET_SHIELDED_POOL_STATE: &str = "getShieldedPoolState";
    /// Get shielded balance using viewing key
    pub const GET_SHIELDED_BALANCE: &str = "getShieldedBalance";
    /// Scan for notes owned by viewing key
    pub const SCAN_NOTES: &str = "scanNotes";
    /// Get Merkle proof for a commitment
    pub const GET_COMMITMENT_PROOF: &str = "getCommitmentProof";
    /// Check if nullifier has been spent
    pub const GET_NULLIFIER_STATUS: &str = "getNullifierStatus";
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_service() -> ShieldedRpcService {
        ShieldedRpcService::new(
            IncrementalMerkleTree::new(),
            NullifierSet::new(),
            ShieldedPoolState::new([0u8; 32]),
        )
    }

    #[test]
    fn test_get_pool_state() {
        let service = create_test_service();
        let response = service.get_pool_state(GetShieldedPoolStateRequest { commitment: None });

        assert_eq!(response.total_shielded, 0);
        assert_eq!(response.commitment_count, 0);
        assert_eq!(response.nullifier_count, 0);
    }

    #[test]
    fn test_get_nullifier_status_unspent() {
        let service = create_test_service();
        let response = service.get_nullifier_status(GetNullifierStatusRequest {
            nullifier: hex::encode([1u8; 32]),
        });

        assert!(!response.spent);
    }

    #[test]
    fn test_get_nullifier_status_invalid() {
        let service = create_test_service();
        let response = service.get_nullifier_status(GetNullifierStatusRequest {
            nullifier: "invalid".to_string(),
        });

        assert!(!response.spent);
    }

    #[test]
    fn test_get_commitment_proof_no_position() {
        let service = create_test_service();
        let response = service.get_commitment_proof(GetCommitmentProofRequest {
            commitment: hex::encode([1u8; 32]),
            position: None,
        });

        assert!(response.proof.is_none());
        assert!(response.error.is_some());
    }

    #[test]
    fn test_scan_notes_empty() {
        let service = create_test_service();
        let response = service.scan_notes(ScanNotesRequest {
            ivk: hex::encode([1u8; 32]),
            start_position: None,
            limit: None,
        });

        assert!(response.notes.is_empty());
        assert!(!response.has_more);
    }

    #[test]
    fn test_get_shielded_balance_zero() {
        let service = create_test_service();
        let response = service.get_shielded_balance(GetShieldedBalanceRequest {
            ivk: hex::encode([1u8; 32]),
            diversifiers: None,
        });

        assert_eq!(response.balance, 0);
        assert_eq!(response.note_count, 0);
    }
}
