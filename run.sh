#!/bin/bash
set -e

echo "=== YaCoin v2 Build & Run ==="

# Kill any existing validator processes
echo "Stopping any running validators..."
pkill -9 -f "yacoin" 2>/dev/null || true
pkill -9 -f "solana" 2>/dev/null || true
pkill -9 -f "validator" 2>/dev/null || true

# Kill processes on validator ports
fuser -k 8899/tcp 2>/dev/null || true
fuser -k 8900/tcp 2>/dev/null || true
fuser -k 9900/tcp 2>/dev/null || true
fuser -k 8000/tcp 2>/dev/null || true
fuser -k 8001/tcp 2>/dev/null || true
fuser -k 8002/tcp 2>/dev/null || true

sleep 2

# Pull latest
echo "Pulling latest changes..."
git fetch origin
git reset --hard origin/master

# Build only what we need
echo "Building validator and CLI..."
cargo build --release -p solana-validator -p solana-cli

echo ""
echo "Build complete!"
echo ""
echo "To start validator:  ./target/release/yacoin-test-validator --reset --account-dir genesis-accounts"
echo "To test shield:      ./target/release/yacoin-shielded-cli shield --amount 100000000 --wallet ~/.yacoin/shielded-wallet.json --keypair ~/.config/solana/id.json"
