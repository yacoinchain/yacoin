#!/bin/bash
set -e

echo "=== YaCoin v2 Build & Run ==="

# Pull latest
echo "Pulling latest changes..."
git pull

# Build only what we need
echo "Building validator and CLI..."
cargo build --release -p solana-validator -p solana-cli

# Setup genesis accounts if not exist
if [ ! -d "genesis-accounts" ]; then
    echo "Setting up genesis accounts..."
    chmod +x setup-genesis.sh
    ./setup-genesis.sh
fi

echo ""
echo "Build complete!"
echo ""
echo "To start validator:  ./target/release/solana-test-validator --reset --account-dir genesis-accounts"
echo "To init pool:        ./target/release/yacoin-shielded-cli init-pool --keypair ~/.config/solana/id.json"
echo "To test shield:      ./target/release/yacoin-shielded-cli shield --amount 100000000 --wallet ~/.yacoin-wallet.json --keypair ~/.config/solana/id.json"
