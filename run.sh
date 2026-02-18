#!/bin/bash
set -e

echo "=== YaCoin v2 Build & Run ==="

# Kill any existing validator processes
echo "Stopping any running validators..."
pkill -9 -f "yacoin" 2>/dev/null || true
pkill -9 -f "solana" 2>/dev/null || true
pkill -9 -f "validator" 2>/dev/null || true

# Kill processes on validator ports using ss (more reliable than fuser)
kill_port() {
    local port=$1
    # Kill TCP
    for pid in $(ss -tlnp 2>/dev/null | grep ":$port " | grep -oP 'pid=\K[0-9]+'); do
        kill -9 $pid 2>/dev/null || true
    done
    # Kill UDP
    for pid in $(ss -ulnp 2>/dev/null | grep ":$port " | grep -oP 'pid=\K[0-9]+'); do
        kill -9 $pid 2>/dev/null || true
    done
}

kill_port 8899
kill_port 8900
kill_port 9900
kill_port 8000
kill_port 8001
kill_port 8002
kill_port 8003
kill_port 8004
kill_port 8005

sleep 2

# Pull latest
echo "Pulling latest changes..."
git fetch origin
git reset --hard origin/master

# Build everything we need (solana-cli includes yacoin-shielded-cli binary)
echo "Building validator and CLI..."
cargo build --release -p solana-validator -p solana-cli

# Regenerate ALL genesis accounts (pool, tree, nullifiers, anchors)
echo ""
echo "Regenerating genesis accounts..."
rm -rf genesis-accounts/*.json
./target/release/yacoin-shielded-cli genesis-accounts -o genesis-accounts

echo ""
echo "Build complete!"
echo ""
echo "Genesis accounts created:"
ls -la genesis-accounts/
echo ""
echo "To start validator:  ./target/release/yacoin-test-validator --reset --account-dir genesis-accounts"
echo "To test shield:      ./target/release/yacoin-shielded-cli shield --amount 100000000 --wallet ~/.yacoin/shielded-wallet.json --keypair ~/.config/solana/id.json"
