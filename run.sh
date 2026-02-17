#!/bin/bash
set -e

echo "=== YaCoin v2 Build & Run ==="

# Pull latest
echo "Pulling latest changes..."
git pull

# Build only what we need
echo "Building validator and CLI..."
cargo build --release -p solana-validator -p solana-cli

echo "Build complete!"
echo ""
echo "To start validator:  solana-test-validator --reset"
echo "To test shield:      ./target/release/yacoin-shielded-cli shield 0.1"
