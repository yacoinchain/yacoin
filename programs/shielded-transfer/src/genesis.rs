//! Genesis configuration for the YaCoin Shielded Pool
//!
//! This module provides the initial state configuration for shielded transactions
//! when bootstrapping a new YaCoin network.

use crate::{
    commitment_tree::IncrementalMerkleTree,
    nullifier_set::NullifierSet,
    state::ShieldedPoolState,
    id,
};

use borsh::{BorshDeserialize, BorshSerialize};

/// Genesis configuration for the shielded pool
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ShieldedPoolGenesis {
    /// Initial pool authority (can be zero for permissionless)
    pub authority: [u8; 32],
    /// Initial shielded pool value (typically 0)
    pub initial_shielded_value: u64,
    /// Merkle tree depth (32 is standard, supports ~4 billion notes)
    pub tree_depth: u8,
    /// Maximum nullifiers per partition
    pub nullifier_partition_size: u64,
}

impl Default for ShieldedPoolGenesis {
    fn default() -> Self {
        Self {
            authority: [0u8; 32], // No authority by default
            initial_shielded_value: 0,
            tree_depth: 32,
            nullifier_partition_size: 1_000_000,
        }
    }
}

impl ShieldedPoolGenesis {
    /// Create a new genesis configuration with custom authority
    pub fn with_authority(authority: [u8; 32]) -> Self {
        Self {
            authority,
            ..Default::default()
        }
    }

    /// Create the initial pool state from genesis config
    pub fn create_pool_state(&self) -> ShieldedPoolState {
        ShieldedPoolState::new(self.authority)
    }

    /// Create the initial commitment tree
    pub fn create_commitment_tree(&self) -> IncrementalMerkleTree {
        IncrementalMerkleTree::new()
    }

    /// Create the initial nullifier set
    pub fn create_nullifier_set(&self) -> NullifierSet {
        NullifierSet::new()
    }

    /// Get the program ID
    pub fn program_id() -> [u8; 32] {
        id::ID.to_bytes()
    }
}

/// Accounts needed at genesis for the shielded pool
pub struct GenesisAccounts {
    /// The shielded pool state account
    pub pool_state: ShieldedPoolState,
    /// The commitment tree (stored off-chain or in separate account)
    pub commitment_tree: IncrementalMerkleTree,
    /// The nullifier set (stored off-chain or in separate account)
    pub nullifier_set: NullifierSet,
}

impl GenesisAccounts {
    /// Create genesis accounts from configuration
    pub fn from_genesis(genesis: &ShieldedPoolGenesis) -> Self {
        Self {
            pool_state: genesis.create_pool_state(),
            commitment_tree: genesis.create_commitment_tree(),
            nullifier_set: genesis.create_nullifier_set(),
        }
    }

    /// Serialize pool state for account data
    pub fn serialize_pool_state(&self) -> Vec<u8> {
        borsh::to_vec(&self.pool_state).expect("Failed to serialize pool state")
    }
}

/// YaCoin network parameters
#[derive(Clone, Debug)]
pub struct YaCoinNetworkParams {
    /// Network name
    pub name: &'static str,
    /// Genesis hash (to be determined at network launch)
    pub genesis_hash: Option<[u8; 32]>,
    /// Shielded pool configuration
    pub shielded_pool: ShieldedPoolGenesis,
}

/// Mainnet configuration
pub fn mainnet() -> YaCoinNetworkParams {
    YaCoinNetworkParams {
        name: "mainnet",
        genesis_hash: None, // To be set at launch
        shielded_pool: ShieldedPoolGenesis::default(),
    }
}

/// Testnet configuration
pub fn testnet() -> YaCoinNetworkParams {
    YaCoinNetworkParams {
        name: "testnet",
        genesis_hash: None,
        shielded_pool: ShieldedPoolGenesis::default(),
    }
}

/// Devnet configuration (for development)
pub fn devnet() -> YaCoinNetworkParams {
    YaCoinNetworkParams {
        name: "devnet",
        genesis_hash: None,
        shielded_pool: ShieldedPoolGenesis {
            // Smaller nullifier partitions for faster testing
            nullifier_partition_size: 10_000,
            ..Default::default()
        },
    }
}

/// Local test configuration
pub fn localnet() -> YaCoinNetworkParams {
    YaCoinNetworkParams {
        name: "localnet",
        genesis_hash: None,
        shielded_pool: ShieldedPoolGenesis {
            nullifier_partition_size: 1_000,
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_default() {
        let genesis = ShieldedPoolGenesis::default();
        assert_eq!(genesis.initial_shielded_value, 0);
        assert_eq!(genesis.tree_depth, 32);
    }

    #[test]
    fn test_create_accounts() {
        let genesis = ShieldedPoolGenesis::default();
        let accounts = GenesisAccounts::from_genesis(&genesis);

        assert_eq!(accounts.pool_state.total_shielded, 0);
        assert_eq!(accounts.commitment_tree.size(), 0);
    }

    #[test]
    fn test_network_params() {
        let mainnet = mainnet();
        assert_eq!(mainnet.name, "mainnet");

        let testnet = testnet();
        assert_eq!(testnet.name, "testnet");

        let devnet = devnet();
        assert_eq!(devnet.name, "devnet");
    }

    #[test]
    fn test_serialize_pool_state() {
        let genesis = ShieldedPoolGenesis::default();
        let accounts = GenesisAccounts::from_genesis(&genesis);
        let serialized = accounts.serialize_pool_state();

        // Should be able to deserialize
        let deserialized: ShieldedPoolState =
            borsh::from_slice(&serialized).expect("Failed to deserialize");
        assert_eq!(deserialized.total_shielded, 0);
    }
}
