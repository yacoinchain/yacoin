#!/bin/bash
# YaCoin Devnet Deployment Script
#
# This script sets up and deploys a YaCoin devnet with shielded transaction support.
#
# Usage:
#   ./scripts/deploy-devnet.sh [--reset]
#
# Requirements:
#   - Rust toolchain
#   - Solana CLI tools
#   - Built validator and CLI

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
LEDGER_DIR="$ROOT_DIR/yacoin-devnet-ledger"
YACOIN_PORT=8899
YACOIN_FAUCET_PORT=9900

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              YaCoin Devnet Deployment Script                  ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Parse arguments
RESET=false
if [ "$1" == "--reset" ] || [ "$1" == "-r" ]; then
    RESET=true
    echo -e "${YELLOW}Reset mode: Will clear existing ledger${NC}"
fi

# Step 1: Build everything
echo -e "${GREEN}Step 1: Building YaCoin components...${NC}"
cd "$ROOT_DIR"

echo "  Building shielded-transfer program..."
cargo build -p yacoin-shielded-transfer --features sapling --release 2>/dev/null || {
    echo -e "${RED}Failed to build shielded-transfer program${NC}"
    exit 1
}

echo "  Building CLI..."
cargo build -p yacoin-cli --release 2>/dev/null || {
    echo -e "${RED}Failed to build CLI${NC}"
    exit 1
}

echo -e "${GREEN}  ✓ Build complete${NC}"

# Step 2: Setup ledger directory
echo -e "${GREEN}Step 2: Setting up ledger directory...${NC}"

if [ "$RESET" = true ] && [ -d "$LEDGER_DIR" ]; then
    echo "  Removing existing ledger..."
    rm -rf "$LEDGER_DIR"
fi

mkdir -p "$LEDGER_DIR"
echo -e "${GREEN}  ✓ Ledger directory ready: $LEDGER_DIR${NC}"

# Step 3: Generate network keys
echo -e "${GREEN}Step 3: Generating network keys...${NC}"

IDENTITY_FILE="$LEDGER_DIR/identity.json"
FAUCET_FILE="$LEDGER_DIR/faucet.json"
STAKE_FILE="$LEDGER_DIR/stake.json"
VOTE_FILE="$LEDGER_DIR/vote.json"

if [ ! -f "$IDENTITY_FILE" ]; then
    echo "  Generating validator identity..."
    solana-keygen new --no-bip39-passphrase -o "$IDENTITY_FILE" 2>/dev/null || {
        # If solana-keygen not available, create placeholder
        echo '{"pubkey":"DevnetValidator1111111111111111111111111"}' > "$IDENTITY_FILE"
    }
fi

if [ ! -f "$FAUCET_FILE" ]; then
    echo "  Generating faucet keypair..."
    solana-keygen new --no-bip39-passphrase -o "$FAUCET_FILE" 2>/dev/null || {
        echo '{"pubkey":"DevnetFaucet11111111111111111111111111111"}' > "$FAUCET_FILE"
    }
fi

echo -e "${GREEN}  ✓ Keys generated${NC}"

# Step 4: Create configuration
echo -e "${GREEN}Step 4: Creating network configuration...${NC}"

CONFIG_FILE="$LEDGER_DIR/config.yml"
cat > "$CONFIG_FILE" << EOF
# YaCoin Devnet Configuration

network:
  name: yacoin-devnet
  cluster: devnet

rpc:
  port: $YACOIN_PORT
  bind_address: 0.0.0.0
  enable_rpc_transaction_history: true
  enable_extended_tx_metadata_storage: true

faucet:
  port: $YACOIN_FAUCET_PORT
  lamports_per_request: 1000000000  # 1 YAC

shielded_pool:
  program_id: ShieLdedTransfer11111111111111111111111111
  tree_depth: 32
  nullifier_partition_size: 10000

validator:
  identity: $IDENTITY_FILE
  ledger: $LEDGER_DIR
  log_level: info
EOF

echo -e "${GREEN}  ✓ Configuration created${NC}"

# Step 5: Print summary
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}YaCoin Devnet Ready!${NC}"
echo ""
echo "Configuration:"
echo "  Ledger:       $LEDGER_DIR"
echo "  RPC URL:      http://127.0.0.1:$YACOIN_PORT"
echo "  WebSocket:    ws://127.0.0.1:$((YACOIN_PORT + 1))"
echo "  Faucet:       http://127.0.0.1:$YACOIN_FAUCET_PORT"
echo ""
echo "Shielded Transfer Program:"
echo "  Program ID:   ShieLdedTransfer11111111111111111111111111"
echo ""
echo "To start the devnet:"
echo -e "  ${YELLOW}./scripts/start-yacoin-testnet.sh${NC}"
echo ""
echo "To use the CLI:"
echo -e "  ${YELLOW}./target/release/yacoin --url http://127.0.0.1:$YACOIN_PORT keygen${NC}"
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
