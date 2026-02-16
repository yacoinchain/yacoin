#!/bin/bash
#
# YaCoin Quick Launch Script
# Starts a local YaCoin network and gives you your first coins
#

set -e

BANNER='
 __   __    _____      _
 \ \ / /_ _/ ____|___ (_)_ __
  \ V / _` | |   / _ \| | '_ \
   | | (_| | |__| (_) | | | | |
   |_|\__,_|\_____\___/|_|_| |_|

  High-Performance Privacy Blockchain
'

echo "$BANNER"
echo "Starting YaCoin Local Network..."
echo ""

# Directories
YACOIN_HOME="$HOME/.yacoin"
LEDGER_DIR="$YACOIN_HOME/test-ledger"
WALLET_DIR="$YACOIN_HOME/wallets"

# Create directories
mkdir -p "$YACOIN_HOME"
mkdir -p "$WALLET_DIR"

# Check for existing keypair or create one
KEYPAIR_FILE="$WALLET_DIR/default.json"
if [ ! -f "$KEYPAIR_FILE" ]; then
    echo "Creating your YaCoin wallet..."
    solana-keygen new -o "$KEYPAIR_FILE" --no-bip39-passphrase --force
    echo ""
fi

PUBKEY=$(solana-keygen pubkey "$KEYPAIR_FILE")
echo "Your YaCoin Address: $PUBKEY"
echo ""

# Configure CLI to use local network
solana config set --url http://127.0.0.1:8899 --keypair "$KEYPAIR_FILE" > /dev/null 2>&1 || true

# Check if validator is already running
if curl -s http://127.0.0.1:8899 -X POST -H "Content-Type: application/json" \
   -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' 2>/dev/null | grep -q "ok"; then
    echo "YaCoin validator is already running!"
else
    echo "Starting YaCoin Test Validator..."
    echo ""

    # Start test validator in background
    if command -v yacoin-test-validator &> /dev/null; then
        yacoin-test-validator --ledger "$LEDGER_DIR" --reset &
    else
        solana-test-validator --ledger "$LEDGER_DIR" --reset &
    fi

    VALIDATOR_PID=$!
    echo "Validator PID: $VALIDATOR_PID"

    # Wait for validator to start
    echo "Waiting for validator to start..."
    for i in {1..30}; do
        if curl -s http://127.0.0.1:8899 -X POST -H "Content-Type: application/json" \
           -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' 2>/dev/null | grep -q "ok"; then
            break
        fi
        sleep 1
        echo -n "."
    done
    echo ""
fi

echo ""
echo "Validator is running!"
echo ""

# Airdrop initial YAC
echo "Airdropping 1000 YAC to your wallet..."
solana airdrop 1000 "$PUBKEY" --url http://127.0.0.1:8899 || true
echo ""

# Show balance
BALANCE=$(solana balance "$PUBKEY" --url http://127.0.0.1:8899 2>/dev/null || echo "0 SOL")
echo "Your Balance: $BALANCE (shown as SOL, but it's YAC!)"
echo ""

# Create shielded wallet if yacoin-cli exists
if command -v yacoin &> /dev/null; then
    SHIELDED_WALLET="$WALLET_DIR/shielded.json"
    if [ ! -f "$SHIELDED_WALLET" ]; then
        echo "Creating shielded wallet..."
        echo "password" | yacoin z-keygen -o "$SHIELDED_WALLET" || true
    fi
fi

echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "YaCoin Local Network is Ready!"
echo ""
echo "  RPC URL:      http://127.0.0.1:8899"
echo "  WebSocket:    ws://127.0.0.1:8900"
echo "  Your Address: $PUBKEY"
echo "  Your Balance: $BALANCE"
echo ""
echo "Commands:"
echo "  solana balance                  # Check balance"
echo "  solana transfer <ADDR> 10      # Send YAC"
echo "  solana airdrop 100             # Get more YAC"
echo ""
echo "Shielded Commands (when yacoin CLI is built):"
echo "  yacoin z-balance -w wallet     # Shielded balance"
echo "  yacoin shield -a 1000000000    # Shield 1 YAC"
echo "  yacoin z-transfer ...          # Private transfer"
echo ""
echo "To stop: pkill solana-test-validator"
echo "═══════════════════════════════════════════════════════════════"
