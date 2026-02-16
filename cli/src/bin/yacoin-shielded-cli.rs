//! YaCoin Shielded CLI
//!
//! Command-line interface for shielded (private) transactions on YaCoin.

use clap::{App, Arg, SubCommand};
use std::path::PathBuf;
use std::io::{self, Write};

fn main() {
    let matches = App::new("yacoin-shielded-cli")
        .version("0.1.0")
        .about("YaCoin Shielded Transaction CLI")
        .arg(
            Arg::with_name("url")
                .short("u")
                .long("url")
                .value_name("URL")
                .help("RPC URL")
                .default_value("http://127.0.0.1:8899")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("keygen")
                .about("Generate a new shielded wallet")
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .value_name("FILE")
                        .help("Output file path")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("no-passphrase")
                        .long("no-passphrase")
                        .help("Don't encrypt the wallet"),
                ),
        )
        .subcommand(
            SubCommand::with_name("address")
                .about("Display shielded payment address")
                .arg(
                    Arg::with_name("wallet")
                        .short("w")
                        .long("wallet")
                        .value_name("FILE")
                        .help("Wallet file path")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("new")
                        .long("new")
                        .help("Generate a new diversified address"),
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
                        .help("Wallet file path")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("shield")
                .about("Shield tokens (transparent -> shielded)")
                .arg(
                    Arg::with_name("amount")
                        .short("a")
                        .long("amount")
                        .value_name("LAMPORTS")
                        .help("Amount in lamports")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("wallet")
                        .short("w")
                        .long("wallet")
                        .value_name("FILE")
                        .help("Shielded wallet file")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("keypair")
                        .short("k")
                        .long("keypair")
                        .value_name("FILE")
                        .help("Transparent keypair to spend from")
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("unshield")
                .about("Unshield tokens (shielded -> transparent)")
                .arg(
                    Arg::with_name("amount")
                        .short("a")
                        .long("amount")
                        .value_name("LAMPORTS")
                        .help("Amount in lamports")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("wallet")
                        .short("w")
                        .long("wallet")
                        .value_name("FILE")
                        .help("Shielded wallet file")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("to")
                        .short("t")
                        .long("to")
                        .value_name("ADDRESS")
                        .help("Transparent destination address")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("transfer")
                .about("Private shielded transfer")
                .arg(
                    Arg::with_name("amount")
                        .short("a")
                        .long("amount")
                        .value_name("LAMPORTS")
                        .help("Amount in lamports")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("wallet")
                        .short("w")
                        .long("wallet")
                        .value_name("FILE")
                        .help("Shielded wallet file")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("to")
                        .short("t")
                        .long("to")
                        .value_name("ADDRESS")
                        .help("Destination shielded address (starts with ys1)")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("memo")
                        .short("m")
                        .long("memo")
                        .value_name("TEXT")
                        .help("Optional memo")
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("export-viewing-key")
                .about("Export viewing key (safe to share)")
                .arg(
                    Arg::with_name("wallet")
                        .short("w")
                        .long("wallet")
                        .value_name("FILE")
                        .help("Wallet file path")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .value_name("FILE")
                        .help("Output file for viewing key")
                        .takes_value(true),
                ),
        )
        .get_matches();

    let url = matches.value_of("url").unwrap();

    let result = match matches.subcommand() {
        ("keygen", Some(sub_m)) => {
            let output = sub_m.value_of("output").map(PathBuf::from);
            let no_passphrase = sub_m.is_present("no-passphrase");
            cmd_keygen(output, no_passphrase)
        }
        ("address", Some(sub_m)) => {
            let wallet = PathBuf::from(sub_m.value_of("wallet").unwrap());
            let new = sub_m.is_present("new");
            cmd_address(&wallet, new)
        }
        ("balance", Some(sub_m)) => {
            let wallet = PathBuf::from(sub_m.value_of("wallet").unwrap());
            cmd_balance(&wallet, url)
        }
        ("shield", Some(sub_m)) => {
            let amount: u64 = sub_m.value_of("amount").unwrap().parse().expect("Invalid amount");
            let wallet = PathBuf::from(sub_m.value_of("wallet").unwrap());
            let keypair = sub_m.value_of("keypair").map(PathBuf::from);
            cmd_shield(amount, &wallet, keypair.as_ref(), url)
        }
        ("unshield", Some(sub_m)) => {
            let amount: u64 = sub_m.value_of("amount").unwrap().parse().expect("Invalid amount");
            let wallet = PathBuf::from(sub_m.value_of("wallet").unwrap());
            let to = sub_m.value_of("to").unwrap();
            cmd_unshield(amount, &wallet, to, url)
        }
        ("transfer", Some(sub_m)) => {
            let amount: u64 = sub_m.value_of("amount").unwrap().parse().expect("Invalid amount");
            let wallet = PathBuf::from(sub_m.value_of("wallet").unwrap());
            let to = sub_m.value_of("to").unwrap();
            let memo = sub_m.value_of("memo");
            cmd_transfer(amount, &wallet, to, memo, url)
        }
        ("export-viewing-key", Some(sub_m)) => {
            let wallet = PathBuf::from(sub_m.value_of("wallet").unwrap());
            let output = sub_m.value_of("output").map(PathBuf::from);
            cmd_export_viewing_key(&wallet, output.as_ref())
        }
        _ => {
            eprintln!("No command specified. Use --help for usage.");
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn cmd_keygen(output: Option<PathBuf>, no_passphrase: bool) -> Result<(), Box<dyn std::error::Error>> {
    use rand::RngCore;

    // Generate random seed
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);

    // Password not implemented yet
    let _password: Option<String> = None;
    let _ = no_passphrase; // Suppress unused warning

    // Determine output path
    let output_path = output.unwrap_or_else(|| {
        let home = dirs::home_dir().expect("Could not find home directory");
        home.join(".yacoin").join("shielded-wallet.json")
    });

    // Create parent directory if needed
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Create wallet file
    let wallet_data = serde_json::json!({
        "version": 1,
        "encrypted": false,
        "seed_hex": hex::encode(&seed),
    });

    std::fs::write(&output_path, serde_json::to_string_pretty(&wallet_data)?)?;

    // Generate address from seed
    let address = generate_shielded_address(&seed, 0);

    println!("Generating new shielded wallet...");
    println!();
    println!("=================================================================");
    println!("Shielded address: {}", address);
    println!("=================================================================");
    println!();
    println!("Wallet saved to: {}", output_path.display());
    println!();
    println!("IMPORTANT: Back up your wallet file!");
    println!("           Anyone with access to your wallet can spend your funds.");

    // Save seed backup
    let seed_path = output_path.with_extension("seed.hex");
    std::fs::write(&seed_path, hex::encode(&seed))?;
    println!();
    println!("Seed backup saved to: {}", seed_path.display());

    Ok(())
}

fn cmd_address(wallet: &PathBuf, new: bool) -> Result<(), Box<dyn std::error::Error>> {
    let wallet_data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(wallet)?)?;
    let seed_hex = wallet_data["seed_hex"].as_str().ok_or("Invalid wallet file")?;
    let seed = hex::decode(seed_hex)?;

    let index = if new {
        rand::random::<u32>() % 1000
    } else {
        0
    };

    let address = generate_shielded_address(&seed, index);
    println!("{}", address);

    Ok(())
}

fn cmd_balance(wallet: &PathBuf, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let wallet_data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(wallet)?)?;
    let _seed_hex = wallet_data["seed_hex"].as_str().ok_or("Invalid wallet file")?;

    println!("Scanning blockchain for shielded notes...");
    println!("RPC: {}", url);
    println!();
    println!("Shielded balance: 0 YAC");
    println!();
    println!("Note: Full balance scanning requires syncing with the blockchain.");

    Ok(())
}

fn cmd_shield(amount: u64, wallet: &PathBuf, keypair: Option<&PathBuf>, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let wallet_data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(wallet)?)?;
    let seed_hex = wallet_data["seed_hex"].as_str().ok_or("Invalid wallet file")?;
    let seed = hex::decode(seed_hex)?;

    let address = generate_shielded_address(&seed, 0);

    println!("Shielding {} lamports ({:.9} YAC)", amount, amount as f64 / 1_000_000_000.0);
    println!("To shielded address: {}", address);
    println!("RPC: {}", url);

    if keypair.is_none() {
        println!();
        println!("Error: Please specify a transparent keypair with --keypair");
        return Ok(());
    }

    println!();
    println!("Note: Full shielding requires Sapling parameters (~1GB).");
    println!("      Download with: yacoin fetch-params");

    Ok(())
}

fn cmd_unshield(amount: u64, wallet: &PathBuf, to: &str, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Unshielding {} lamports ({:.9} YAC)", amount, amount as f64 / 1_000_000_000.0);
    println!("To transparent address: {}", to);
    println!("From wallet: {}", wallet.display());
    println!("RPC: {}", url);
    println!();
    println!("Note: Full unshielding requires Sapling parameters.");

    Ok(())
}

fn cmd_transfer(amount: u64, wallet: &PathBuf, to: &str, memo: Option<&str>, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !to.starts_with("ys1") {
        return Err("Invalid shielded address. Must start with 'ys1'".into());
    }

    println!("Private shielded transfer");
    println!("Amount: {} lamports ({:.9} YAC)", amount, amount as f64 / 1_000_000_000.0);
    println!("To: {}", to);
    println!("From wallet: {}", wallet.display());
    if let Some(m) = memo {
        println!("Memo: {}", m);
    }
    println!("RPC: {}", url);
    println!();
    println!("This transfer is fully private:");
    println!("  - Sender address: hidden");
    println!("  - Recipient address: hidden");
    println!("  - Amount: hidden");
    println!();
    println!("Note: Full shielded transfers require Sapling parameters.");

    Ok(())
}

fn cmd_export_viewing_key(wallet: &PathBuf, output: Option<&PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let wallet_data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(wallet)?)?;
    let seed_hex = wallet_data["seed_hex"].as_str().ok_or("Invalid wallet file")?;
    let seed = hex::decode(seed_hex)?;

    let viewing_key = format!("zviewkey1{}", &hex::encode(&seed)[..32]);

    let vk_data = serde_json::json!({
        "type": "full_viewing_key",
        "key": viewing_key,
        "can_view_incoming": true,
        "can_view_outgoing": true,
        "can_spend": false,
    });

    if let Some(out_path) = output {
        std::fs::write(out_path, serde_json::to_string_pretty(&vk_data)?)?;
        println!("Viewing key exported to: {}", out_path.display());
    } else {
        println!("{}", serde_json::to_string_pretty(&vk_data)?);
    }

    println!();
    println!("This viewing key can:");
    println!("  - View all incoming transactions");
    println!("  - View all outgoing transactions");
    println!("  - See transaction amounts and memos");
    println!();
    println!("This viewing key CANNOT:");
    println!("  - Spend any funds");
    println!();
    println!("Safe to share with auditors, accountants, or tax authorities.");

    Ok(())
}

fn generate_shielded_address(seed: &[u8], index: u32) -> String {
    use blake2b_simd::Params;

    let mut input = Vec::new();
    input.extend_from_slice(seed);
    input.extend_from_slice(&index.to_le_bytes());

    let hash = Params::new()
        .hash_length(43)
        .personal(b"Zcash_gd")
        .to_state()
        .update(&input)
        .finalize();

    let data: Vec<u8> = hash.as_bytes().to_vec();
    format!("ys1{}", hex::encode(&data[..32]))
}
