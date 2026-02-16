#!/bin/bash
# YaCoin Parameter Download Script
#
# Downloads the Sapling zk-SNARK parameters required for shielded transactions.
# These parameters are the same as Zcash Sapling parameters (~65MB total).
#
# Usage:
#   ./scripts/fetch-params.sh [--dir <path>]

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default parameter directory
PARAMS_DIR="${YACOIN_PARAMS:-$HOME/.yacoin/params}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dir)
            PARAMS_DIR="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--dir <path>]"
            echo ""
            echo "Downloads Sapling zk-SNARK parameters for YaCoin shielded transactions."
            echo ""
            echo "Options:"
            echo "  --dir <path>  Directory to store parameters (default: ~/.yacoin/params)"
            echo "  -h, --help    Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           YaCoin Sapling Parameter Downloader                 ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Create directory
mkdir -p "$PARAMS_DIR"
echo -e "${GREEN}Parameter directory: $PARAMS_DIR${NC}"
echo ""

# Parameter URLs (using Zcash's official parameters)
SPEND_URL="https://download.z.cash/downloads/sapling-spend.params"
OUTPUT_URL="https://download.z.cash/downloads/sapling-output.params"

# Expected SHA256 hashes
SPEND_HASH="8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13"
OUTPUT_HASH="2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4"

# File sizes for progress indication
SPEND_SIZE="49848572"  # ~49MB
OUTPUT_SIZE="16034676" # ~16MB

download_param() {
    local name=$1
    local url=$2
    local expected_hash=$3
    local file_path="$PARAMS_DIR/$name"

    echo -e "${YELLOW}Downloading $name...${NC}"

    if [ -f "$file_path" ]; then
        echo "  File exists, verifying..."
        local actual_hash=$(sha256sum "$file_path" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$file_path" | cut -d' ' -f1)
        if [ "$actual_hash" = "$expected_hash" ]; then
            echo -e "  ${GREEN}✓ Already downloaded and verified${NC}"
            return 0
        else
            echo -e "  ${RED}Hash mismatch, re-downloading...${NC}"
            rm "$file_path"
        fi
    fi

    # Download with progress
    if command -v curl &> /dev/null; then
        curl -L --progress-bar -o "$file_path" "$url"
    elif command -v wget &> /dev/null; then
        wget --show-progress -O "$file_path" "$url"
    else
        echo -e "${RED}Error: curl or wget required${NC}"
        exit 1
    fi

    # Verify hash
    echo "  Verifying hash..."
    local actual_hash=$(sha256sum "$file_path" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$file_path" | cut -d' ' -f1)
    if [ "$actual_hash" = "$expected_hash" ]; then
        echo -e "  ${GREEN}✓ Verified${NC}"
    else
        echo -e "  ${RED}✗ Hash verification failed!${NC}"
        echo "  Expected: $expected_hash"
        echo "  Got:      $actual_hash"
        rm "$file_path"
        exit 1
    fi
}

# Download parameters
download_param "sapling-spend.params" "$SPEND_URL" "$SPEND_HASH"
download_param "sapling-output.params" "$OUTPUT_URL" "$OUTPUT_HASH"

# Also create symlink in Zcash standard location for compatibility
ZCASH_PARAMS="$HOME/.zcash-params"
if [ ! -d "$ZCASH_PARAMS" ]; then
    mkdir -p "$ZCASH_PARAMS"
fi

# Create symlinks if they don't exist
if [ ! -f "$ZCASH_PARAMS/sapling-spend.params" ]; then
    ln -sf "$PARAMS_DIR/sapling-spend.params" "$ZCASH_PARAMS/sapling-spend.params" 2>/dev/null || true
fi
if [ ! -f "$ZCASH_PARAMS/sapling-output.params" ]; then
    ln -sf "$PARAMS_DIR/sapling-output.params" "$ZCASH_PARAMS/sapling-output.params" 2>/dev/null || true
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Sapling parameters downloaded successfully!${NC}"
echo ""
echo "Parameters location: $PARAMS_DIR"
echo ""
echo "Files:"
ls -lh "$PARAMS_DIR"/*.params 2>/dev/null || echo "  (files listed above)"
echo ""
echo -e "You can now run YaCoin with shielded transactions enabled."
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
