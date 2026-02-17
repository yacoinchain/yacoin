#!/bin/bash
set -e

echo "=== Setting up YaCoin Shielded Pool Genesis Accounts ==="

# Program ID (must match yacoin_shielded_transfer::id::ID)
PROGRAM_ID="6cbBWQ4cQzoETCkuyrnCfgtHz7r4oLyCT4YghiNe7pJU"

# PDAs (pre-computed for this program ID)
POOL_PDA="FfuR6yCrrFskgrWYPzc8VQa5piCksL93a33tMB3UsXjp"
TREE_PDA="7AXDB9ApfK5YiDE2iQcyTFjMyScDkaWiogdmp6SoQtuE"
NULLIFIER_PDA="of5iaUYEQkvAeoQbpwBFgDqudTP5ZHB94eLeBSxvPNR"
ANCHOR_PDA="CgK6TjaehogG3waQCS4Li1aFdTfJ9xNq91Px31iNcDhD"

# Create accounts directory
mkdir -p genesis-accounts

# Generate base64 encoded zeros for each account size
# Pool: 128 bytes, Tree: 2048 bytes, Nullifier: 256 bytes, Anchor: 4096 bytes
POOL_DATA=$(python3 -c "import base64; print(base64.b64encode(b'\\x00'*128).decode())")
TREE_DATA=$(python3 -c "import base64; print(base64.b64encode(b'\\x00'*2048).decode())")
NULLIFIER_DATA=$(python3 -c "import base64; print(base64.b64encode(b'\\x00'*256).decode())")
ANCHOR_DATA=$(python3 -c "import base64; print(base64.b64encode(b'\\x00'*4096).decode())")

# Pool account (flattened CliAccount format)
cat > genesis-accounts/${POOL_PDA}.json << EOF
{
  "pubkey": "${POOL_PDA}",
  "account": {
    "lamports": 1000000000,
    "data": ["${POOL_DATA}", "base64"],
    "owner": "${PROGRAM_ID}",
    "executable": false,
    "rentEpoch": 0
  }
}
EOF

# Tree account
cat > genesis-accounts/${TREE_PDA}.json << EOF
{
  "pubkey": "${TREE_PDA}",
  "account": {
    "lamports": 1000000000,
    "data": ["${TREE_DATA}", "base64"],
    "owner": "${PROGRAM_ID}",
    "executable": false,
    "rentEpoch": 0
  }
}
EOF

# Nullifier account
cat > genesis-accounts/${NULLIFIER_PDA}.json << EOF
{
  "pubkey": "${NULLIFIER_PDA}",
  "account": {
    "lamports": 1000000000,
    "data": ["${NULLIFIER_DATA}", "base64"],
    "owner": "${PROGRAM_ID}",
    "executable": false,
    "rentEpoch": 0
  }
}
EOF

# Anchor account
cat > genesis-accounts/${ANCHOR_PDA}.json << EOF
{
  "pubkey": "${ANCHOR_PDA}",
  "account": {
    "lamports": 1000000000,
    "data": ["${ANCHOR_DATA}", "base64"],
    "owner": "${PROGRAM_ID}",
    "executable": false,
    "rentEpoch": 0
  }
}
EOF

echo "Created genesis accounts in ./genesis-accounts/"
echo ""
echo "Pool: $POOL_PDA"
echo "Tree: $TREE_PDA"
echo "Nullifier: $NULLIFIER_PDA"
echo "Anchor: $ANCHOR_PDA"
echo ""
echo "Start validator with: ./target/release/solana-test-validator --reset --account-dir genesis-accounts"
