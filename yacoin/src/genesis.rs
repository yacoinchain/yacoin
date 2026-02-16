//! YaCoin Genesis
//!
//! Create genesis configuration for a new YaCoin network.

use std::env;
use std::process::{Command, exit};

const VERSION: &str = "0.1.0";

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && (args[1] == "--help" || args[1] == "-h") {
        print_help();
        return;
    }

    if args.len() > 1 && (args[1] == "--version" || args[1] == "-V") {
        println!("yacoin-genesis {}", VERSION);
        return;
    }

    // Find and run solana-genesis
    let solana_genesis = find_binary("solana-genesis")
        .unwrap_or_else(|| "solana-genesis".to_string());

    let mut cmd = Command::new(&solana_genesis);

    // Pass through all arguments
    for arg in &args[1..] {
        cmd.arg(arg);
    }

    match cmd.status() {
        Ok(status) => exit(status.code().unwrap_or(0)),
        Err(e) => {
            eprintln!("Failed to run genesis: {}", e);
            exit(1);
        }
    }
}

fn print_help() {
    println!("YaCoin Genesis v{}", VERSION);
    println!();
    println!("USAGE:");
    println!("    yacoin-genesis [OPTIONS]");
    println!();
    println!("DESCRIPTION:");
    println!("    Create genesis configuration for a new YaCoin network.");
    println!("    This includes initial token allocations, validator setup,");
    println!("    and shielded pool initialization.");
    println!();
    println!("OPTIONS:");
    println!("    --bootstrap-validator <IDENTITY> <VOTE> <STAKE>");
    println!("                            Initial validator keys");
    println!("    --faucet-pubkey <PUBKEY> Faucet public key");
    println!("    --faucet-lamports <AMOUNT> Initial faucet balance");
    println!("    --ledger <PATH>         Output ledger directory");
    println!("    --hashes-per-tick <NUM> PoH hashes per tick");
    println!();
    println!("EXAMPLE: Create local testnet genesis");
    println!();
    println!("    # Generate validator keys");
    println!("    yacoin-keygen new -o identity.json");
    println!("    yacoin-keygen new -o vote.json");
    println!("    yacoin-keygen new -o stake.json");
    println!("    yacoin-keygen new -o faucet.json");
    println!();
    println!("    # Create genesis");
    println!("    yacoin-genesis \\");
    println!("        --bootstrap-validator identity.json vote.json stake.json \\");
    println!("        --faucet-pubkey $(yacoin-keygen pubkey faucet.json) \\");
    println!("        --faucet-lamports 1000000000000000000 \\");
    println!("        --ledger genesis-ledger");
    println!();
    println!("TOKEN DISTRIBUTION:");
    println!("    YaCoin uses lamports internally (1 YAC = 1,000,000,000 lamports)");
    println!("    --faucet-lamports 1000000000000000000 = 1,000,000,000 YAC");
}

fn find_binary(name: &str) -> Option<String> {
    if let Ok(path) = which::which(name) {
        return Some(path.to_string_lossy().to_string());
    }
    None
}
