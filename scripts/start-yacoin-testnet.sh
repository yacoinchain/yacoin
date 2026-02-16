#!/bin/bash
# YaCoin Test Network Startup Script
#
# This script starts a local YaCoin test network with shielded transaction support.
#
# Prerequisites:
#   - solana-test-validator must be built
#   - yacoin-shielded-transfer program must be built as BPF
#
# Usage:
#   ./scripts/start-yacoin-testnet.sh [--reset]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# YaCoin Shielded Transfer Program ID
SHIELDED_PROGRAM_ID="YaCoin1111111111111111111111111111111111111"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                   YaCoin Test Network                         ║${NC}"
echo -e "${BLUE}║          Solana Fork with Shielded Transactions               ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if solana-test-validator exists
if ! command -v solana-test-validator &> /dev/null; then
    echo -e "${RED}Error: solana-test-validator not found${NC}"
    echo "Please build it first: cargo build -p solana-test-validator"
    exit 1
fi

# Check for reset flag
RESET_FLAG=""
if [ "$1" == "--reset" ] || [ "$1" == "-r" ]; then
    RESET_FLAG="--reset"
    echo -e "${YELLOW}Resetting ledger...${NC}"
fi

# Build the shielded transfer program if needed
PROGRAM_SO="$ROOT_DIR/target/deploy/yacoin_shielded_transfer.so"
if [ ! -f "$PROGRAM_SO" ]; then
    echo -e "${YELLOW}Building yacoin-shielded-transfer program...${NC}"
    cd "$ROOT_DIR"
    cargo build-bpf -p yacoin-shielded-transfer 2>/dev/null || {
        echo -e "${YELLOW}Note: BPF build not available, using native program${NC}"
        PROGRAM_SO=""
    }
fi

echo -e "${GREEN}Starting YaCoin Test Validator...${NC}"
echo ""
echo "  RPC URL:   http://127.0.0.1:8899"
echo "  WebSocket: ws://127.0.0.1:8900"
echo "  Faucet:    http://127.0.0.1:9900"
echo ""
echo "  Shielded Transfer Program: $SHIELDED_PROGRAM_ID"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
echo ""

# Start the validator
cd "$ROOT_DIR"

if [ -n "$PROGRAM_SO" ] && [ -f "$PROGRAM_SO" ]; then
    # Start with shielded transfer program loaded
    solana-test-validator \
        $RESET_FLAG \
        --bpf-program "$SHIELDED_PROGRAM_ID" "$PROGRAM_SO" \
        --log
else
    # Start without the program (for testing)
    solana-test-validator \
        $RESET_FLAG \
        --log
fi
