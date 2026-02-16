//! YaCoin Keygen
//!
//! Generate keypairs for YaCoin accounts and validators.

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
        println!("yacoin-keygen {}", VERSION);
        return;
    }

    // Find and run solana-keygen
    let solana_keygen = find_binary("solana-keygen")
        .unwrap_or_else(|| "solana-keygen".to_string());

    let mut cmd = Command::new(&solana_keygen);

    // Pass through all arguments
    for arg in &args[1..] {
        cmd.arg(arg);
    }

    match cmd.status() {
        Ok(status) => exit(status.code().unwrap_or(0)),
        Err(e) => {
            eprintln!("Failed to run keygen: {}", e);
            exit(1);
        }
    }
}

fn print_help() {
    println!("YaCoin Keygen v{}", VERSION);
    println!();
    println!("USAGE:");
    println!("    yacoin-keygen <COMMAND>");
    println!();
    println!("COMMANDS:");
    println!("    new         Generate new keypair");
    println!("    pubkey      Display public key");
    println!("    recover     Recover keypair from seed phrase");
    println!("    grind       Grind for vanity keypair");
    println!("    verify      Verify keypair");
    println!();
    println!("EXAMPLES:");
    println!("    # Generate new keypair");
    println!("    yacoin-keygen new -o my-wallet.json");
    println!();
    println!("    # Generate with BIP39 passphrase");
    println!("    yacoin-keygen new --word-count 24 -o secure-wallet.json");
    println!();
    println!("    # Show public key");
    println!("    yacoin-keygen pubkey my-wallet.json");
    println!();
    println!("    # Grind for vanity address (starts with 'yac')");
    println!("    yacoin-keygen grind --starts-with yac:1");
    println!();
    println!("NOTE: For shielded wallet generation, use:");
    println!("    yacoin z-keygen");
}

fn find_binary(name: &str) -> Option<String> {
    if let Ok(path) = which::which(name) {
        return Some(path.to_string_lossy().to_string());
    }
    None
}
