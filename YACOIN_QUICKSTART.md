# YaCoin Quick Start Guide

YaCoin is a high-performance blockchain with full transaction privacy, featuring Sapling zk-SNARK privacy technology.

## Features

- **Shielded Transactions**: Hide sender, recipient, and amount
- **High Throughput**: Built on YaCoin's parallel execution engine
- **zk-SNARK Proofs**: Groth16 proving system for privacy
- **Compatible Tooling**: Works with standard blockchain development tools

## Prerequisites

1. Rust toolchain (1.70+)
2. ~1GB disk space for Sapling parameters

## Setup

### 1. Download Sapling Parameters

```bash
./scripts/fetch-params.sh
```

This downloads the cryptographic parameters needed for proof generation/verification.

### 2. Build YaCoin

```bash
cargo build --release
```

### 3. Start Test Validator

```bash
./target/release/yacoin-test-validator
```

## CLI Usage

### Create a Shielded Wallet

```bash
yacoin keygen
```

This generates:
- An encrypted wallet file (`~/.yacoin/wallet.json`)
- A seed backup file (`~/.yacoin/wallet.seed.hex`)

### Get Payment Address

```bash
# Default address
yacoin address -w ~/.yacoin/wallet.json

# Generate new unique address
yacoin address -w ~/.yacoin/wallet.json --new
```

Shielded addresses start with `ys1`.

### Shield Tokens (Transparent → Shielded)

```bash
yacoin shield -a 1000000000 -w ~/.yacoin/wallet.json
```

This creates a shielded note worth 1 YAC (1 billion yacs).

### Shielded Transfer

```bash
yacoin transfer -a 500000000 -t ys1... -w ~/.yacoin/wallet.json
```

Transfer between shielded addresses - completely private!

### Unshield (Shielded → Transparent)

```bash
yacoin unshield -a 100000000 -t <yacoin-pubkey> -w ~/.yacoin/wallet.json
```

### Check Balance

```bash
yacoin balance -w ~/.yacoin/wallet.json
```

### Export Viewing Key

```bash
yacoin export-viewing-key -w ~/.yacoin/wallet.json -o viewing_key.json
```

Viewing keys can monitor balance without spending ability.

### Backup/Restore

```bash
# Create backup
yacoin backup -w ~/.yacoin/wallet.json -o backup.json

# Restore from backup
yacoin restore -b backup.json -o restored_wallet.json
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      YaCoin Blockchain                       │
├─────────────────────────────────────────────────────────────┤
│  YaCoin Runtime (PoH, parallel execution, ~65k TPS)         │
├─────────────────────────────────────────────────────────────┤
│  Shielded Transfer Program (native builtin)                 │
│  ├── Shield: transparent → shielded                         │
│  ├── Unshield: shielded → transparent                       │
│  └── Transfer: shielded → shielded                          │
├─────────────────────────────────────────────────────────────┤
│  Cryptography                                                │
│  ├── Groth16 zk-SNARKs (BLS12-381)                          │
│  ├── Jubjub curve (Pedersen commitments)                    │
│  ├── ChaCha20-Poly1305 (note encryption)                    │
│  └── Incremental Merkle tree (note commitments)             │
└─────────────────────────────────────────────────────────────┘
```

## Key Concepts

### Notes
A shielded "note" is like a private UTXO containing:
- Value (hidden)
- Recipient address (hidden)
- Random commitment trapdoor

### Nullifiers
Prevent double-spending. Each note has a unique nullifier derived from the spending key.

### Value Commitments
Pedersen commitments prove value balance without revealing amounts.

### Viewing Keys
Derived from spending key. Can decrypt incoming transactions but cannot spend.

## Development

### Run Tests

```bash
# All shielded transfer tests
cargo test -p yacoin-shielded-transfer

# Wallet SDK tests
cargo test -p yacoin-shielded-wallet

# Full e2e test
./scripts/test-shielded.sh
```

### Project Structure

```
solana/
├── programs/shielded-transfer/    # Core shielded transfer program
│   ├── src/
│   │   ├── crypto/               # Cryptographic primitives
│   │   │   ├── groth16.rs       # zk-SNARK verification
│   │   │   ├── keys.rs          # Key derivation
│   │   │   ├── note.rs          # Note encryption
│   │   │   └── pedersen.rs      # Pedersen hashing
│   │   ├── commitment_tree.rs   # Merkle tree
│   │   ├── nullifier_set.rs     # Double-spend prevention
│   │   ├── processor.rs         # Instruction processing
│   │   └── native.rs            # Native runtime integration
├── sdk/shielded-wallet/          # Wallet SDK
│   ├── src/
│   │   ├── wallet.rs            # High-level wallet interface
│   │   ├── transaction.rs       # Transaction building
│   │   └── keys.rs              # Key management
├── yacoin-cli/                   # CLI application
├── builtins/                     # Native builtin registration
└── scripts/
    ├── fetch-params.sh          # Download Sapling params
    └── test-shielded.sh         # E2E test script
```

## Security Notes

1. **Backup your seed**: The seed file can recover your wallet
2. **Keep spending key secret**: Anyone with it can spend your funds
3. **Viewing keys are safe to share**: They only allow balance monitoring
4. **Use strong passwords**: Wallet files are encrypted with ChaCha20-Poly1305

## License

Apache 2.0
