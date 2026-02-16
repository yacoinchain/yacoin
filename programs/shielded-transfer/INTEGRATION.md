# YaCoin Shielded Transfer - Runtime Integration

This document describes how to integrate the shielded transfer program as a native builtin in the YaCoin runtime.

## Overview

The shielded transfer program can run in two modes:
1. **BPF Program** - Deployed as a standard YaCoin program
2. **Native Builtin** - Embedded directly in the validator runtime (recommended for production)

## Native Builtin Integration

### Step 1: Enable the Native Feature

Build the program with the `native` feature:

```bash
cargo build -p yacoin-shielded-transfer --features native
```

### Step 2: Register in Builtins

Add the following to `builtins/src/lib.rs`:

```rust
// Add import at the top
use yacoin_shielded_transfer;

// Add to BUILTINS array
testable_prototype!(BuiltinPrototype {
    core_bpf_migration_config: None,
    name: yacoin_shielded_transfer_program,
    enable_feature_id: None,  // Always enabled for YaCoin
    program_id: yacoin_shielded_transfer::id::id(),
    entrypoint: yacoin_shielded_transfer::Entrypoint::vm,
}),
```

### Step 3: Add Dependency

Add to `builtins/Cargo.toml`:

```toml
yacoin-shielded-transfer = { path = "../programs/shielded-transfer", features = ["native"] }
```

## Program ID

The shielded transfer program uses a deterministic ID:

```
ShieLdedTransfer11111111111111111111111111
```

Byte representation:
```rust
[
    0x53, 0x68, 0x69, 0x65, 0x4c, 0x64, 0x65, 0x64, // "ShieLded"
    0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, // "Transfer"
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, // "11111111"
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, // "11111111"
]
```

## Instructions

| Instruction | Code | Description |
|-------------|------|-------------|
| Shield | 0 | Convert transparent tokens to shielded |
| Unshield | 1 | Convert shielded tokens to transparent |
| ShieldedTransfer | 2 | Transfer between shielded addresses |

## Compute Budget

Shielded operations require significant compute units due to zk-SNARK verification:

- Default: 1,000,000 CUs
- Shield: ~500,000 CUs (output proof verification)
- Unshield: ~500,000 CUs (spend proof verification)
- ShieldedTransfer: ~1,000,000 CUs (both proofs)

## State Accounts

The program manages these state accounts:

1. **Shielded Pool** - Tracks total shielded value
2. **Commitment Tree** - Merkle tree of note commitments
3. **Nullifier Set** - Tracks spent notes to prevent double-spending

## Testing

Run tests with:

```bash
cargo test -p yacoin-shielded-transfer --features native
```

## Security Considerations

1. **zk-SNARK Verification** - Proofs must be verified before accepting any shielded transaction
2. **Double-Spend Prevention** - Nullifiers must be checked and stored atomically
3. **Anchor Validation** - Only recent Merkle roots should be accepted
