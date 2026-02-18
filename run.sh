#!/bin/bash
set -e

# If not already pulled, pull and re-exec
if [ "$YACOIN_PULLED" != "1" ]; then
    echo "=== YaCoin v2 Build & Run ==="
    echo "Pulling latest from git..."
    git fetch origin
    git reset --hard origin/master
    export YACOIN_PULLED=1
    exec bash "$0" "$@"
fi

echo "Stopping any running validators..."
pkill -9 -f "yacoin" 2>/dev/null || true
pkill -9 -f "solana" 2>/dev/null || true
pkill -9 -f "validator" 2>/dev/null || true
sleep 1

# Kill ALL processes on validator ports (aggressive)
for port in 8000 8001 8002 8003 8004 8005 8899 8900 9900; do
    # Kill by ss TCP
    for pid in $(ss -tlnp 2>/dev/null | grep ":$port" | grep -oP 'pid=\K[0-9]+' | sort -u); do
        kill -9 $pid 2>/dev/null || true
    done
    # Kill by ss UDP
    for pid in $(ss -ulnp 2>/dev/null | grep ":$port" | grep -oP 'pid=\K[0-9]+' | sort -u); do
        kill -9 $pid 2>/dev/null || true
    done
    # Kill by lsof as backup
    for pid in $(lsof -ti:$port 2>/dev/null); do
        kill -9 $pid 2>/dev/null || true
    done
done

sleep 2

# Verify ports are free
for port in 8000 8899; do
    if ss -tlnp | grep -q ":$port"; then
        echo "WARNING: Port $port still in use!"
        ss -tlnp | grep ":$port"
    fi
done

# Build
echo "Building validator and CLI..."
cargo build --release -p solana-validator -p solana-cli

# Regenerate ALL genesis accounts
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

# Auto-start validator if --start flag is passed
if [ "$1" = "--start" ] || [ "$1" = "-s" ]; then
    echo "Starting validator..."
    ./target/release/yacoin-test-validator --reset --account-dir genesis-accounts
else
    echo "To start validator:  ./target/release/yacoin-test-validator --reset --account-dir genesis-accounts"
    echo "Or run:              bash run.sh --start"
    echo ""
    echo "To test shield:      ./target/release/yacoin-shielded-cli shield --amount 100000000 --wallet ~/.yacoin/shielded-wallet.json --keypair ~/.config/solana/id.json"
fi
