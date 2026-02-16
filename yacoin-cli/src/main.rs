//! YaCoin CLI - Command line interface for shielded transactions
//!
//! Commands:
//! - keygen: Generate new shielded wallet
//! - address: Get payment address
//! - shield: Convert transparent tokens to shielded
//! - unshield: Convert shielded tokens to transparent
//! - transfer: Shielded to shielded transfer
//! - balance: Check shielded balance
//!
//! Connect to YaCoin network:
//!   yacoin --url http://127.0.0.1:8899 <command>

use clap::{App, Arg, SubCommand};
use rand::RngCore;
use std::fs;
use std::path::PathBuf;
use std::io::{self, Write};
use solana_pubkey::Pubkey;
use solana_client::rpc_client::RpcClient;

use yacoin_shielded_wallet::{
    ShieldedWallet, ShieldedAddress,
    WalletBackup,
};

/// Default YaCoin RPC URL (local test validator)
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";

/// Get the shielded pool program ID
fn shielded_pool_pubkey() -> Pubkey {
    yacoin_shielded_transfer::id::ID
}

fn main() {
    let matches = App::new("yacoin")
        .version("0.1.0")
        .author("YaCoin Team")
        .about("YaCoin CLI for shielded transactions")
        .arg(
            Arg::with_name("url")
                .short("u")
                .long("url")
                .value_name("URL")
                .help("YaCoin RPC URL (default: http://127.0.0.1:8899)")
                .takes_value(true)
                .global(true),
        )
        .subcommand(
            SubCommand::with_name("keygen")
                .about("Generate new shielded wallet")
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .value_name("FILE")
                        .help("Output wallet file (default: ~/.yacoin/wallet.json)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("seed")
                        .long("seed")
                        .value_name("HEX")
                        .help("Use specific seed (hex encoded, for recovery)")
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("address")
                .about("Get payment address")
                .arg(
                    Arg::with_name("wallet")
                        .short("w")
                        .long("wallet")
                        .value_name("FILE")
                        .help("Path to wallet file")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("new")
                        .short("n")
                        .long("new")
                        .help("Generate a new unique address"),
                ),
        )
        .subcommand(
            SubCommand::with_name("shield")
                .about("Shield transparent tokens")
                .arg(
                    Arg::with_name("amount")
                        .short("a")
                        .long("amount")
                        .value_name("YACS")
                        .help("Amount to shield (in yacs, 1 YAC = 1e9 yacs)")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("wallet")
                        .short("w")
                        .long("wallet")
                        .value_name("FILE")
                        .help("Path to wallet file")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("unshield")
                .about("Unshield tokens to transparent address")
                .arg(
                    Arg::with_name("amount")
                        .short("a")
                        .long("amount")
                        .value_name("YACS")
                        .help("Amount to unshield (in yacs)")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("to")
                        .short("t")
                        .long("to")
                        .value_name("PUBKEY")
                        .help("Recipient transparent address")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("wallet")
                        .short("w")
                        .long("wallet")
                        .value_name("FILE")
                        .help("Path to wallet file")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("transfer")
                .about("Shielded to shielded transfer")
                .arg(
                    Arg::with_name("amount")
                        .short("a")
                        .long("amount")
                        .value_name("YACS")
                        .help("Amount to transfer (in yacs)")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("to")
                        .short("t")
                        .long("to")
                        .value_name("ADDRESS")
                        .help("Recipient shielded address (ys1...)")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("wallet")
                        .short("w")
                        .long("wallet")
                        .value_name("FILE")
                        .help("Path to wallet file")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("balance")
                .about("Check shielded balance")
                .arg(
                    Arg::with_name("wallet")
                        .short("w")
                        .long("wallet")
                        .value_name("FILE")
                        .help("Path to wallet file")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("export-viewing-key")
                .about("Export viewing key (safe to share for balance monitoring)")
                .arg(
                    Arg::with_name("wallet")
                        .short("w")
                        .long("wallet")
                        .value_name("FILE")
                        .help("Path to wallet file")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .value_name("FILE")
                        .help("Output file for viewing key")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("backup")
                .about("Create encrypted wallet backup")
                .arg(
                    Arg::with_name("wallet")
                        .short("w")
                        .long("wallet")
                        .value_name("FILE")
                        .help("Path to wallet file")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .value_name("FILE")
                        .help("Output file for backup")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("restore")
                .about("Restore wallet from encrypted backup")
                .arg(
                    Arg::with_name("backup")
                        .short("b")
                        .long("backup")
                        .value_name("FILE")
                        .help("Path to backup file")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .value_name("FILE")
                        .help("Output wallet file")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .get_matches();

    let rpc_url = matches.value_of("url").unwrap_or(DEFAULT_RPC_URL);

    match matches.subcommand() {
        ("keygen", Some(args)) => cmd_keygen(args),
        ("address", Some(args)) => cmd_address(args),
        ("shield", Some(args)) => cmd_shield(args, rpc_url),
        ("unshield", Some(args)) => cmd_unshield(args, rpc_url),
        ("transfer", Some(args)) => cmd_transfer(args, rpc_url),
        ("balance", Some(args)) => cmd_balance(args, rpc_url),
        ("export-viewing-key", Some(args)) => cmd_export_viewing_key(args),
        ("backup", Some(args)) => cmd_backup(args),
        ("restore", Some(args)) => cmd_restore(args),
        _ => {
            println!("YaCoin - Shielded Transaction CLI");
            println!();
            println!("Commands:");
            println!("  keygen              Generate new wallet");
            println!("  address             Get payment address");
            println!("  shield              Shield transparent tokens");
            println!("  unshield            Unshield to transparent");
            println!("  transfer            Shielded transfer");
            println!("  balance             Check shielded balance");
            println!("  export-viewing-key  Export viewing key");
            println!("  backup              Create encrypted backup");
            println!("  restore             Restore from backup");
            println!();
            println!("Use --help to see all options");
        }
    }
}

/// Load a wallet from file
fn load_wallet(path: &str, password: &str) -> Result<ShieldedWallet, String> {
    let data = fs::read_to_string(path).map_err(|e| format!("Failed to read wallet: {}", e))?;
    let backup: WalletBackup =
        serde_json::from_str(&data).map_err(|e| format!("Invalid wallet format: {}", e))?;
    ShieldedWallet::import_encrypted(&backup, password)
        .map_err(|e| format!("Failed to decrypt wallet: {:?}", e))
}

/// Save a wallet to file
fn save_wallet(wallet: &ShieldedWallet, path: &str, password: &str) -> Result<(), String> {
    let backup = wallet
        .export_encrypted(password)
        .map_err(|e| format!("Failed to encrypt wallet: {:?}", e))?;
    let json = serde_json::to_string_pretty(&backup)
        .map_err(|e| format!("Failed to serialize: {}", e))?;
    fs::write(path, json).map_err(|e| format!("Failed to write wallet: {}", e))
}

/// Prompt for password
fn prompt_password(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();

    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();
    password.trim().to_string()
}

fn cmd_keygen(args: &clap::ArgMatches) {
    println!("Generating new shielded wallet...");

    let seed: [u8; 32] = if let Some(seed_hex) = args.value_of("seed") {
        let bytes = hex::decode(seed_hex).expect("Invalid hex seed");
        if bytes.len() != 32 {
            eprintln!("Seed must be 32 bytes (64 hex characters)");
            std::process::exit(1);
        }
        bytes.try_into().unwrap()
    } else {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        seed
    };

    // Create wallet from seed
    let mut wallet = ShieldedWallet::from_seed(&seed);

    // Get default address
    let address = wallet.default_address().expect("Failed to generate address");

    // Default output path
    let output_path = args.value_of("output").map(PathBuf::from).unwrap_or_else(|| {
        let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".yacoin").join("wallet.json")
    });

    // Create directory if needed
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).expect("Failed to create directory");
    }

    // Get password
    let password = prompt_password("Enter wallet password: ");
    let confirm = prompt_password("Confirm password: ");

    if password != confirm {
        eprintln!("Passwords do not match!");
        std::process::exit(1);
    }

    // Save wallet
    save_wallet(&wallet, output_path.to_str().unwrap(), &password)
        .expect("Failed to save wallet");

    // Also save seed for backup
    let seed_path = output_path.with_extension("seed.hex");
    fs::write(&seed_path, hex::encode(seed)).expect("Failed to write seed");

    println!();
    println!("Wallet created successfully!");
    println!();
    println!("Wallet file: {}", output_path.display());
    println!("Seed backup: {}", seed_path.display());
    println!();
    println!("Default payment address:");
    println!("  {}", address.to_string());
    println!();
    println!("IMPORTANT: Back up your seed file securely!");
}

fn cmd_address(args: &clap::ArgMatches) {
    let wallet_path = args.value_of("wallet").unwrap();
    let generate_new = args.is_present("new");

    let password = prompt_password("Wallet password: ");

    let mut wallet = load_wallet(wallet_path, &password).expect("Failed to load wallet");

    let address = if generate_new {
        wallet.new_address().expect("Failed to generate address")
    } else {
        wallet.default_address().expect("Failed to get address")
    };

    // Save wallet if we generated a new address
    if generate_new {
        save_wallet(&wallet, wallet_path, &password).expect("Failed to save wallet");
        println!("New payment address:");
    } else {
        println!("Default payment address:");
    }
    println!("  {}", address.to_string());
}

fn cmd_shield(args: &clap::ArgMatches, rpc_url: &str) {
    let amount: u64 = args.value_of("amount").unwrap().parse().expect("Invalid amount");
    let wallet_path = args.value_of("wallet").unwrap();

    let password = prompt_password("Wallet password: ");
    let mut wallet = load_wallet(wallet_path, &password).expect("Failed to load wallet");

    // Build the instruction
    let from_account = Pubkey::default(); // Would be loaded from YaCoin keypair
    let pool_account = shielded_pool_pubkey();

    let instruction = wallet
        .create_shield_instruction(amount, from_account, pool_account)
        .expect("Failed to create shield instruction");

    println!("Shield Transaction:");
    println!("  Amount: {} yacs ({:.9} YAC)", amount, amount as f64 / 1e9);
    println!("  Pool: {}", pool_account);
    println!("  Data: {} bytes", instruction.data.len());
    println!();

    // Check RPC connection
    let client = RpcClient::new(rpc_url.to_string());
    match client.get_version() {
        Ok(version) => {
            println!("Connected to node: {:?}", version);
            println!();
            println!("To submit: sign with YaCoin keypair and send transaction");
        }
        Err(e) => {
            println!("RPC not available: {}", e);
            println!("Transaction prepared but not submitted.");
        }
    }
}

fn cmd_unshield(args: &clap::ArgMatches, rpc_url: &str) {
    let amount: u64 = args.value_of("amount").unwrap().parse().expect("Invalid amount");
    let to_str = args.value_of("to").unwrap();
    let wallet_path = args.value_of("wallet").unwrap();

    let to_pubkey: Pubkey = to_str.parse().expect("Invalid recipient pubkey");
    let password = prompt_password("Wallet password: ");
    let wallet = load_wallet(wallet_path, &password).expect("Failed to load wallet");

    let pool_account = shielded_pool_pubkey();

    println!("Unshield Transaction:");
    println!("  Amount: {} yacs ({:.9} YAC)", amount, amount as f64 / 1e9);
    println!("  To: {}", to_pubkey);
    println!();

    // Check balance
    let spendable = wallet.spendable_balance();
    println!("Spendable balance: {} yacs", spendable);

    if spendable < amount {
        eprintln!("Insufficient balance: have {}, need {}", spendable, amount);
        std::process::exit(1);
    }

    let instruction = wallet
        .create_unshield_instruction(amount, to_pubkey, pool_account)
        .expect("Failed to create unshield instruction");

    println!("Instruction data: {} bytes", instruction.data.len());

    let client = RpcClient::new(rpc_url.to_string());
    if client.get_version().is_ok() {
        println!("Transaction prepared for submission.");
    }
}

fn cmd_transfer(args: &clap::ArgMatches, rpc_url: &str) {
    let amount: u64 = args.value_of("amount").unwrap().parse().expect("Invalid amount");
    let to_str = args.value_of("to").unwrap();
    let wallet_path = args.value_of("wallet").unwrap();

    let to_address = ShieldedAddress::from_string(to_str)
        .expect("Invalid shielded address (should start with ys1)");

    let password = prompt_password("Wallet password: ");
    let wallet = load_wallet(wallet_path, &password).expect("Failed to load wallet");

    let pool_account = shielded_pool_pubkey();

    println!("Shielded Transfer:");
    println!("  Amount: {} yacs ({:.9} YAC)", amount, amount as f64 / 1e9);
    println!("  To: {}", to_str);
    println!();

    let spendable = wallet.spendable_balance();
    if spendable < amount {
        eprintln!("Insufficient balance: have {}, need {}", spendable, amount);
        std::process::exit(1);
    }

    let instruction = wallet
        .create_transfer_instruction(amount, to_address, pool_account)
        .expect("Failed to create transfer instruction");

    println!("Instruction data: {} bytes", instruction.data.len());

    let client = RpcClient::new(rpc_url.to_string());
    if client.get_version().is_ok() {
        println!("Transaction prepared for submission.");
    }
}

fn cmd_balance(args: &clap::ArgMatches, rpc_url: &str) {
    let wallet_path = args.value_of("wallet").unwrap();

    let password = prompt_password("Wallet password: ");
    let wallet = load_wallet(wallet_path, &password).expect("Failed to load wallet");

    println!("Shielded Balance:");
    println!("  Total: {} yacs ({:.9} YAC)", wallet.balance(), wallet.balance() as f64 / 1e9);
    println!("  Spendable: {} yacs ({:.9} YAC)", wallet.spendable_balance(), wallet.spendable_balance() as f64 / 1e9);
    println!();

    let client = RpcClient::new(rpc_url.to_string());
    if let Ok(version) = client.get_version() {
        println!("Node: {:?}", version);
    }

    if wallet.balance() == 0 {
        println!();
        println!("Note: To see incoming transactions, scan the blockchain.");
    }
}

fn cmd_export_viewing_key(args: &clap::ArgMatches) {
    let wallet_path = args.value_of("wallet").unwrap();
    let output_path = args.value_of("output").unwrap();

    let password = prompt_password("Wallet password: ");
    let wallet = load_wallet(wallet_path, &password).expect("Failed to load wallet");

    let export = wallet.export_viewing_key();
    let json = serde_json::to_string_pretty(&export).expect("Failed to serialize");
    fs::write(output_path, json).expect("Failed to write file");

    println!("Viewing key exported to: {}", output_path);
    println!();
    println!("This key can safely be shared for balance monitoring.");
    println!("It CANNOT be used to spend funds.");
}

fn cmd_backup(args: &clap::ArgMatches) {
    let wallet_path = args.value_of("wallet").unwrap();
    let output_path = args.value_of("output").unwrap();

    let password = prompt_password("Wallet password: ");
    let wallet = load_wallet(wallet_path, &password).expect("Failed to load wallet");

    let backup_pass = prompt_password("Backup password: ");
    let confirm = prompt_password("Confirm backup password: ");

    if backup_pass != confirm {
        eprintln!("Passwords do not match!");
        std::process::exit(1);
    }

    let backup = wallet.export_encrypted(&backup_pass).expect("Failed to create backup");
    let json = serde_json::to_string_pretty(&backup).expect("Failed to serialize");
    fs::write(output_path, json).expect("Failed to write backup");

    println!("Backup created: {}", output_path);
}

fn cmd_restore(args: &clap::ArgMatches) {
    let backup_path = args.value_of("backup").unwrap();
    let output_path = args.value_of("output").unwrap();

    let data = fs::read_to_string(backup_path).expect("Failed to read backup");
    let backup: WalletBackup = serde_json::from_str(&data).expect("Invalid backup format");

    let backup_pass = prompt_password("Backup password: ");
    let wallet = ShieldedWallet::import_encrypted(&backup, &backup_pass).expect("Failed to restore");

    let new_pass = prompt_password("New wallet password: ");
    let confirm = prompt_password("Confirm password: ");

    if new_pass != confirm {
        eprintln!("Passwords do not match!");
        std::process::exit(1);
    }

    save_wallet(&wallet, output_path, &new_pass).expect("Failed to save wallet");
    println!("Wallet restored: {}", output_path);
}
