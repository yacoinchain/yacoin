//! YaCoin CLI
//!
//! Unified command-line interface for YaCoin blockchain.
//! Wraps Solana commands with YaCoin branding + adds shielded transaction support.
//!
//! Usage:
//!   yacoin [OPTIONS] <COMMAND>
//!
//! Standard Commands (Solana-compatible):
//!   balance       Check account balance
//!   transfer      Send YAC tokens
//!   airdrop       Request airdrop (devnet/testnet)
//!   account       Display account info
//!   config        Manage configuration
//!
//! Shielded Commands (Privacy):
//!   shield        Convert transparent → shielded
//!   unshield      Convert shielded → transparent
//!   z-transfer    Private shielded transfer
//!   z-balance     Check shielded balance
//!   z-keygen      Generate shielded wallet

use std::env;
use std::process::{Command, exit};

const VERSION: &str = "0.1.0";
const BANNER: &str = r#"
 __   __    _____      _
 \ \ / /_ _/ ____|___ (_)_ __
  \ V / _` | |   / _ \| | '_ \
   | | (_| | |__| (_) | | | | |
   |_|\__,_|\_____\___/|_|_| |_|

  High-Performance Privacy Blockchain
"#;

fn main() {
    let args: Vec<String> = env::args().collect();

    // No args or help
    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_help();
        return;
    }

    // Version
    if args[1] == "--version" || args[1] == "-V" {
        println!("yacoin {}", VERSION);
        return;
    }

    let command = &args[1];
    let remaining_args: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();

    match command.as_str() {
        // === Shielded Commands (Native YaCoin) ===
        "shield" | "z-shield" => run_shielded_cli("shield", &remaining_args),
        "unshield" | "z-unshield" => run_shielded_cli("unshield", &remaining_args),
        "z-transfer" | "ztransfer" => run_shielded_cli("transfer", &remaining_args),
        "z-balance" | "zbalance" => run_shielded_cli("balance", &remaining_args),
        "z-keygen" | "zkeygen" => run_shielded_cli("keygen", &remaining_args),
        "z-address" | "zaddress" => run_shielded_cli("address", &remaining_args),
        "viewing-key" => run_shielded_cli("export-viewing-key", &remaining_args),

        // === Standard Commands (Proxy to Solana CLI) ===
        "balance" => run_solana_cli("balance", &remaining_args),
        "transfer" => run_solana_cli("transfer", &remaining_args),
        "airdrop" => run_solana_cli("airdrop", &remaining_args),
        "account" => run_solana_cli("account", &remaining_args),
        "config" => run_solana_cli("config", &remaining_args),
        "address" => run_solana_cli("address", &remaining_args),
        "stake" => run_solana_cli("stake", &remaining_args),
        "vote" => run_solana_cli("vote", &remaining_args),
        "program" => run_solana_cli("program", &remaining_args),
        "transaction" => run_solana_cli("transaction", &remaining_args),
        "decode" => run_solana_cli("decode", &remaining_args),

        // === Validator Commands ===
        "validator" => {
            eprintln!("Use 'yacoin-validator' to run a validator node");
            exit(1);
        }

        // Unknown - try Solana CLI
        _ => {
            eprintln!("Unknown command: {}", command);
            eprintln!("Run 'yacoin --help' for available commands");
            exit(1);
        }
    }
}

fn print_help() {
    println!("{}", BANNER);
    println!("YaCoin CLI v{}", VERSION);
    println!();
    println!("USAGE:");
    println!("    yacoin [OPTIONS] <COMMAND>");
    println!();
    println!("SHIELDED COMMANDS (Private Transactions):");
    println!("    z-keygen        Generate new shielded wallet");
    println!("    z-address       Get shielded payment address");
    println!("    z-balance       Check shielded balance");
    println!("    shield          Convert transparent YAC → shielded");
    println!("    unshield        Convert shielded → transparent YAC");
    println!("    z-transfer      Private shielded-to-shielded transfer");
    println!("    viewing-key     Export viewing key (safe to share)");
    println!();
    println!("TRANSPARENT COMMANDS (Solana-compatible):");
    println!("    balance         Check transparent account balance");
    println!("    transfer        Send transparent YAC tokens");
    println!("    airdrop         Request airdrop (devnet/testnet only)");
    println!("    address         Display wallet address");
    println!("    account         Display account info");
    println!("    config          Manage CLI configuration");
    println!("    stake           Stake management");
    println!("    vote            Vote account management");
    println!("    program         Deploy and manage programs");
    println!();
    println!("OPTIONS:");
    println!("    -u, --url <URL>     RPC URL (default: http://127.0.0.1:8899)");
    println!("    -k, --keypair <PATH> Path to keypair file");
    println!("    -h, --help          Print help");
    println!("    -V, --version       Print version");
    println!();
    println!("EXAMPLES:");
    println!("    # Generate shielded wallet");
    println!("    yacoin z-keygen -o ~/.yacoin/wallet.json");
    println!();
    println!("    # Shield 100 YAC");
    println!("    yacoin shield -a 100000000000 -w ~/.yacoin/wallet.json");
    println!();
    println!("    # Private transfer");
    println!("    yacoin z-transfer -a 50000000000 -t ys1... -w ~/.yacoin/wallet.json");
    println!();
    println!("    # Check balances");
    println!("    yacoin balance                    # Transparent");
    println!("    yacoin z-balance -w wallet.json   # Shielded");
    println!();
    println!("NETWORK:");
    println!("    Mainnet:  https://api.yacoin.io");
    println!("    Testnet:  https://testnet.yacoin.io");
    println!("    Devnet:   https://devnet.yacoin.io");
    println!("    Local:    http://127.0.0.1:8899");
}

/// Run a shielded CLI command
fn run_shielded_cli(subcommand: &str, args: &[&str]) {
    let yacoin_cli = find_binary("yacoin-shielded-cli")
        .unwrap_or_else(|| "yacoin-shielded-cli".to_string());

    let mut cmd = Command::new(&yacoin_cli);
    cmd.arg(subcommand);
    cmd.args(args);

    match cmd.status() {
        Ok(status) => {
            if !status.success() {
                exit(status.code().unwrap_or(1));
            }
        }
        Err(e) => {
            eprintln!("Failed to run shielded CLI: {}", e);
            eprintln!("Make sure yacoin-shielded-cli is installed and in your PATH");
            exit(1);
        }
    }
}

/// Run a Solana CLI command with YaCoin environment
fn run_solana_cli(subcommand: &str, args: &[&str]) {
    // Try to find solana binary
    let solana_cli = find_binary("solana")
        .unwrap_or_else(|| "solana".to_string());

    let mut cmd = Command::new(&solana_cli);
    cmd.arg(subcommand);
    cmd.args(args);

    // Set YaCoin-specific environment
    cmd.env("SOLANA_METRICS_CONFIG", "");  // Disable Solana metrics

    match cmd.status() {
        Ok(status) => {
            if !status.success() {
                exit(status.code().unwrap_or(1));
            }
        }
        Err(e) => {
            eprintln!("Failed to run command: {}", e);
            eprintln!("Make sure solana CLI tools are installed");
            exit(1);
        }
    }
}

/// Find binary in PATH or relative locations
fn find_binary(name: &str) -> Option<String> {
    // Check if it's in PATH
    if let Ok(path) = which::which(name) {
        return Some(path.to_string_lossy().to_string());
    }

    // Check relative to current executable
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
