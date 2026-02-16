//! YaCoin Validator
//!
//! Wrapper around solana-validator with YaCoin branding and defaults.
//!
//! Usage:
//!   yacoin-validator [OPTIONS]
//!
//! This is a full validator node for the YaCoin network.

use std::env;
use std::process::{Command, exit};

const VERSION: &str = "0.1.0";

fn main() {
    let args: Vec<String> = env::args().collect();

    // Check for help/version
    if args.len() > 1 {
        match args[1].as_str() {
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--version" | "-V" => {
                println!("yacoin-validator {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    println!("Starting YaCoin Validator...");
    println!();

    // Find and run solana-validator
    let solana_validator = find_binary("solana-validator")
        .unwrap_or_else(|| "solana-validator".to_string());

    let mut cmd = Command::new(&solana_validator);

    // Pass through all arguments (skip program name)
    for arg in &args[1..] {
        cmd.arg(arg);
    }

    // Set YaCoin-specific environment
    cmd.env("SOLANA_METRICS_CONFIG", "");  // Disable Solana metrics by default

    match cmd.status() {
        Ok(status) => {
            if !status.success() {
                exit(status.code().unwrap_or(1));
            }
        }
        Err(e) => {
            eprintln!("Failed to start validator: {}", e);
            eprintln!();
            eprintln!("Make sure solana-validator is installed:");
            eprintln!("  cargo install solana-validator");
            exit(1);
        }
    }
}

fn print_help() {
    println!("YaCoin Validator v{}", VERSION);
    println!();
    println!("USAGE:");
    println!("    yacoin-validator [OPTIONS]");
    println!();
    println!("DESCRIPTION:");
    println!("    Run a full YaCoin validator node. This participates in");
    println!("    consensus, validates transactions, and processes shielded");
    println!("    transaction proofs.");
    println!();
    println!("COMMON OPTIONS:");
    println!("    --identity <KEYPAIR>    Validator identity keypair");
    println!("    --ledger <PATH>         Use ledger at this path");
    println!("    --rpc-port <PORT>       RPC port (default: 8899)");
    println!("    --gossip-port <PORT>    Gossip port (default: 8001)");
    println!("    --dynamic-port-range <MIN-MAX>  Dynamic port range");
    println!("    --entrypoint <HOST:PORT>  Entrypoint to connect to");
    println!("    --expected-genesis-hash <HASH>  Expected genesis hash");
    println!();
    println!("QUICK START:");
    println!("    # Generate validator identity");
    println!("    yacoin-keygen new -o validator-keypair.json");
    println!();
    println!("    # Start local validator (for development)");
    println!("    yacoin-test-validator");
    println!();
    println!("    # Join testnet");
    println!("    yacoin-validator \\");
    println!("        --identity validator-keypair.json \\");
    println!("        --ledger ledger \\");
    println!("        --entrypoint testnet.yacoin.io:8001");
    println!();
    println!("For all options: yacoin-validator --help-all");
}

fn find_binary(name: &str) -> Option<String> {
    if let Ok(path) = which::which(name) {
        return Some(path.to_string_lossy().to_string());
    }

    if let Ok(exe_path) = env::current_exe() {
        if let Some(dir) = exe_path.parent() {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }

    None
}
