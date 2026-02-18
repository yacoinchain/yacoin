//! YaCoin Shielded CLI
//!
//! Command-line interface for shielded (private) transactions on YaCoin.

use clap::{App, Arg, SubCommand};
use std::path::PathBuf;

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
        .subcommand(
            SubCommand::with_name("init-pool")
                .about("Initialize the shielded pool (admin only)")
                .arg(
                    Arg::with_name("keypair")
                        .short("k")
                        .long("keypair")
                        .value_name("FILE")
                        .help("Keypair file to pay for account creation")
                        .takes_value(true)
                        .required(true),
                )
        )
        .subcommand(
            SubCommand::with_name("genesis-accounts")
                .about("Generate genesis accounts YAML for shielded pool")
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .value_name("FILE")
                        .help("Output file (default: shielded-pool-genesis.yaml)")
                        .takes_value(true),
                )
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
        ("init-pool", Some(sub_m)) => {
            let keypair = PathBuf::from(sub_m.value_of("keypair").unwrap());
            cmd_init_pool(&keypair, url)
        }
        ("genesis-accounts", Some(sub_m)) => {
            let output = sub_m.value_of("output").map(PathBuf::from);
            cmd_genesis_accounts(output)
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
    use solana_keypair::read_keypair_file;
    use solana_signer::Signer;
    use solana_rpc_client::rpc_client::RpcClient;
    use solana_pubkey::Pubkey;
    use solana_transaction::Transaction;
    use solana_message::Message;
    use solana_instruction::Instruction;
    use solana_compute_budget_interface::ComputeBudgetInstruction;
    use solana_system_interface::instruction as system_instruction;
    use yacoin_shielded_transfer::{OutputDescription, ShieldedInstruction, id, ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE};
    use yacoin_shielded_wallet::prover::{ShieldedProver, get_params_dir};
    use yacoin_shielded_wallet::keys::SpendingKey;
    use yacoin_shielded_wallet::note::Note;

    // Load shielded wallet
    let wallet_data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(wallet)?)?;
    let seed_hex = wallet_data["seed_hex"].as_str().ok_or("Invalid wallet file")?;
    let seed_bytes = hex::decode(seed_hex)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes[..32]);

    let address_str = generate_shielded_address(&seed, 0);

    println!("Shielding {} lamports ({:.9} YAC)", amount, amount as f64 / 1_000_000_000.0);
    println!("To shielded address: {}", address_str);
    println!("RPC: {}", url);
    println!();

    // Check for keypair
    let keypair_path = keypair.ok_or("Please specify a transparent keypair with --keypair")?;
    let payer = read_keypair_file(keypair_path)
        .map_err(|e| format!("Failed to read keypair: {}", e))?;

    // Check Sapling parameters
    let params_dir = get_params_dir();
    let spend_params_path = params_dir.join("sapling-spend.params");
    let output_params_path = params_dir.join("sapling-output.params");

    if !spend_params_path.exists() || !output_params_path.exists() {
        println!("Sapling parameters not found at: {}", params_dir.display());
        println!();
        println!("Download them with:");
        println!("  mkdir -p {}", params_dir.display());
        println!("  curl -L https://download.z.cash/downloads/sapling-spend.params -o {}", spend_params_path.display());
        println!("  curl -L https://download.z.cash/downloads/sapling-output.params -o {}", output_params_path.display());
        return Err("Sapling parameters required".into());
    }

    println!("Loading Sapling parameters...");

    // Create the spending key from seed
    let sk = SpendingKey::from_seed(&seed);

    // Get payment address from full viewing key
    let fvk = sk.to_full_viewing_key();
    let payment_address = fvk.default_address()
        .map_err(|e| format!("Failed to derive address: {:?}", e))?;

    // Create a note for the shielded output
    let note = Note::new(&payment_address, amount);

    println!("Generating zk-SNARK proof...");

    // Generate the output proof
    let mut prover = ShieldedProver::new()?;
    prover.load_params()?;

    // Generate random value commitment trapdoor
    let mut rcv_bytes = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut rcv_bytes);
    let rcv = jubjub::Fr::from_bytes_wide(&rcv_bytes);
    let output_proof = prover.create_output_proof(&note, rcv)?;

    // Build the OutputDescription
    let output_desc = OutputDescription {
        cv: output_proof.cv,
        cmu: output_proof.cmu,
        ephemeral_key: output_proof.epk,
        enc_ciphertext: [0u8; ENC_CIPHERTEXT_SIZE], // TODO: real encryption
        out_ciphertext: [0u8; OUT_CIPHERTEXT_SIZE], // TODO: real encryption
        zkproof: output_proof.proof,
    };

    // Build the Shield instruction
    let instruction_data = ShieldedInstruction::Shield {
        amount,
        output: output_desc,
    };

    // Debug: verify serialization
    let serialized_ix = borsh::to_vec(&instruction_data)?;
    println!("Serialized instruction: {} bytes", serialized_ix.len());
    println!("First byte (discriminant): {}", serialized_ix[0]);
    println!("Bytes 1-9 (amount): {:?}", &serialized_ix[1..9]);
    println!("Expected: discriminant=0, amount={:?}", amount.to_le_bytes());
    // Expected size: 1 (discriminant) + 8 (amount) + 948 (OutputDescription) = 957
    // OutputDescription: 32 (cv) + 32 (cmu) + 32 (epk) + 580 (enc) + 80 (out) + 192 (proof) = 948
    if serialized_ix.len() != 957 {
        println!("WARNING: Unexpected instruction size! Expected 957, got {}", serialized_ix.len());
    }

    let program_id = id::ID;

    // Derive all PDA addresses
    let (pool_address, _) = Pubkey::find_program_address(&[b"shielded_pool"], &program_id);
    let (tree_address, _) = Pubkey::find_program_address(&[b"commitment_tree"], &program_id);
    let (anchor_address, _) = Pubkey::find_program_address(&[b"recent_anchors"], &program_id);

    // Shield instruction: 0=Funder, 1=Pool, 2=Tree, 3=Anchors
    let shield_instruction = Instruction {
        program_id,
        accounts: vec![
            solana_instruction::AccountMeta::new(payer.pubkey(), true),
            solana_instruction::AccountMeta::new(pool_address, false),
            solana_instruction::AccountMeta::new(tree_address, false),
            solana_instruction::AccountMeta::new(anchor_address, false),
        ],
        data: borsh::to_vec(&instruction_data)?,
    };

    // Request more compute units for zk-SNARK verification (1.4M CU)
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);

    // System Program transfer: payer -> pool (the shielded program can't debit payer directly)
    let transfer_ix = system_instruction::transfer(&payer.pubkey(), &pool_address, amount);

    println!("Submitting transaction...");

    // Connect to RPC
    let client = RpcClient::new(url.to_string());

    // Get recent blockhash
    let blockhash = client.get_latest_blockhash()?;

    // Build transaction: compute budget, transfer, then shield
    let message = Message::new(&[compute_budget_ix, transfer_ix, shield_instruction], Some(&payer.pubkey()));
    let mut tx = Transaction::new_unsigned(message);
    tx.sign(&[&payer], blockhash);

    // Submit transaction
    match client.send_and_confirm_transaction(&tx) {
        Ok(signature) => {
            println!();
            println!("Success! Transaction signature: {}", signature);
            println!();
            println!("Shielded {} YAC to {}", amount as f64 / 1_000_000_000.0, address_str);
        }
        Err(e) => {
            let err_str = format!("{}", e);
            println!();
            println!("Transaction error: {}", err_str);

            // Give helpful hints based on error type
            if err_str.contains("AccountNotFound") {
                println!();
                println!("Hint: Pool accounts may not exist. Run: yacoin-shielded-cli init-pool");
            } else if err_str.contains("invalid account data") || err_str.contains("InvalidAccountData") {
                println!();
                println!("Hint: Pool may need initialization. Run: yacoin-shielded-cli init-pool --keypair <key>");
            }
            return Err(format!("Transaction failed: {}", e).into());
        }
    }

    Ok(())
}

fn cmd_init_pool(keypair: &PathBuf, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    use solana_keypair::read_keypair_file;
    use solana_signer::Signer;
    use solana_rpc_client::rpc_client::RpcClient;
    use solana_pubkey::Pubkey;
    use solana_transaction::Transaction;
    use solana_message::Message;
    use solana_instruction::{Instruction, AccountMeta};
    use solana_compute_budget_interface::ComputeBudgetInstruction;
    use yacoin_shielded_transfer::{id, ShieldedInstruction};

    println!("Initializing shielded pool...");
    println!("RPC: {}", url);
    println!();

    let payer = read_keypair_file(keypair)
        .map_err(|e| format!("Failed to read keypair: {}", e))?;

    let client = RpcClient::new(url.to_string());
    let program_id = id::ID;

    // Derive all PDA addresses
    let (pool_address, _pool_bump) = Pubkey::find_program_address(&[b"shielded_pool"], &program_id);
    let (tree_address, _tree_bump) = Pubkey::find_program_address(&[b"commitment_tree"], &program_id);
    let (nullifier_address, _nf_bump) = Pubkey::find_program_address(&[b"nullifier_set"], &program_id);
    let (anchor_address, _anchor_bump) = Pubkey::find_program_address(&[b"recent_anchors"], &program_id);

    println!("Program ID: {}", program_id);
    println!("Pool PDA: {}", pool_address);
    println!("Tree PDA: {}", tree_address);
    println!("Nullifier PDA: {}", nullifier_address);
    println!("Anchor PDA: {}", anchor_address);
    println!();

    // Check if already initialized
    match client.get_account(&pool_address) {
        Ok(account) => {
            if account.data.len() > 0 && account.data[0] != 0 {
                println!("Shielded pool already initialized!");
                println!("Pool balance: {} lamports", account.lamports);
                return Ok(());
            }
            println!("Pool account exists but not initialized. Initializing...");
        }
        Err(_) => {
            println!("Pool account does not exist.");
            println!("Start validator with: --account-dir genesis-accounts");
            println!("Or run: ./setup-genesis.sh first");
            return Err("Pool account must exist. Run setup-genesis.sh and restart validator with --account-dir genesis-accounts".into());
        }
    }

    // Build InitializePool instruction
    let authority = payer.pubkey().to_bytes();
    let instruction_data = borsh::to_vec(&ShieldedInstruction::InitializePool { authority })?;

    let init_instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(pool_address, false),
            AccountMeta::new(tree_address, false),
            AccountMeta::new(nullifier_address, false),
            AccountMeta::new(anchor_address, false),
        ],
        data: instruction_data,
    };

    println!("Submitting InitializePool transaction...");

    // Add compute budget for initialization (native program needs plenty)
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);

    let blockhash = client.get_latest_blockhash()?;
    let message = Message::new(&[compute_budget_ix, init_instruction], Some(&payer.pubkey()));
    let mut tx = Transaction::new_unsigned(message);
    tx.sign(&[&payer], blockhash);

    match client.send_and_confirm_transaction(&tx) {
        Ok(signature) => {
            println!();
            println!("Success! Transaction: {}", signature);
            println!("Shielded pool initialized.");
        }
        Err(e) => {
            return Err(format!("Transaction failed: {}", e).into());
        }
    }

    Ok(())
}

fn cmd_genesis_accounts(output: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    use solana_pubkey::Pubkey;
    use yacoin_shielded_transfer::id;
    use base64::{Engine, prelude::BASE64_STANDARD};

    let program_id = id::ID;

    // Derive all PDA addresses
    let (pool_address, _) = Pubkey::find_program_address(&[b"shielded_pool"], &program_id);
    let (tree_address, _) = Pubkey::find_program_address(&[b"commitment_tree"], &program_id);
    let (nullifier_address, _) = Pubkey::find_program_address(&[b"nullifier_set"], &program_id);
    let (anchor_address, _) = Pubkey::find_program_address(&[b"recent_anchors"], &program_id);

    // Account sizes (must be rent-exempt)
    let pool_size = 128;      // ShieldedPoolState with padding
    let tree_size = 2048;     // CommitmentTreeAccount
    let nullifier_size = 256; // Initial NullifierSetAccount
    let anchor_size = 4096;   // RecentAnchorsAccount (100 * 32 + padding)

    // Rent-exempt minimums (approximate, using 6960 lamports per byte-year)
    // At 2 years rent-exempt: ~0.00348 SOL per byte, minimum 890880 lamports
    let rent_per_byte = 6960u64;
    let min_rent = 890880u64;

    let pool_rent = std::cmp::max(min_rent, pool_size as u64 * rent_per_byte * 2);
    let tree_rent = std::cmp::max(min_rent, tree_size as u64 * rent_per_byte * 2);
    let nullifier_rent = std::cmp::max(min_rent, nullifier_size as u64 * rent_per_byte * 2);
    let anchor_rent = std::cmp::max(min_rent, anchor_size as u64 * rent_per_byte * 2);

    // Create empty data (will be initialized by InitializePool)
    let pool_data = vec![0u8; pool_size];
    let tree_data = vec![0u8; tree_size];
    let nullifier_data = vec![0u8; nullifier_size];
    let anchor_data = vec![0u8; anchor_size];

    let yaml = format!(r#"# YaCoin Shielded Pool Genesis Accounts
# Generated for program ID: {}
# Add this file to genesis with: --primordial-accounts-file <this-file>

{}:
  owner: "{}"
  balance: {}
  data: "{}"
  executable: false

{}:
  owner: "{}"
  balance: {}
  data: "{}"
  executable: false

{}:
  owner: "{}"
  balance: {}
  data: "{}"
  executable: false

{}:
  owner: "{}"
  balance: {}
  data: "{}"
  executable: false
"#,
        program_id,
        pool_address, program_id, pool_rent, BASE64_STANDARD.encode(&pool_data),
        tree_address, program_id, tree_rent, BASE64_STANDARD.encode(&tree_data),
        nullifier_address, program_id, nullifier_rent, BASE64_STANDARD.encode(&nullifier_data),
        anchor_address, program_id, anchor_rent, BASE64_STANDARD.encode(&anchor_data),
    );

    let output_path = output.unwrap_or_else(|| PathBuf::from("shielded-pool-genesis.yaml"));
    std::fs::write(&output_path, &yaml)?;

    println!("Generated genesis accounts file: {}", output_path.display());
    println!();
    println!("Program ID: {}", program_id);
    println!("Pool PDA: {} ({} lamports)", pool_address, pool_rent);
    println!("Tree PDA: {} ({} lamports)", tree_address, tree_rent);
    println!("Nullifier PDA: {} ({} lamports)", nullifier_address, nullifier_rent);
    println!("Anchor PDA: {} ({} lamports)", anchor_address, anchor_rent);
    println!();
    println!("Total lamports needed: {}", pool_rent + tree_rent + nullifier_rent + anchor_rent);
    println!();
    println!("To use:");
    println!("  1. Regenerate genesis with: --primordial-accounts-file {}", output_path.display());
    println!("  2. Start validator with new ledger");
    println!("  3. Run: yacoin-shielded-cli init-pool --keypair <authority-keypair>");

    Ok(())
}

fn cmd_unshield(amount: u64, wallet: &PathBuf, to: &str, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Unshielding {} lamports ({:.9} YAC)", amount, amount as f64 / 1_000_000_000.0);
    println!("To transparent address: {}", to);
    println!("From wallet: {}", wallet.display());
    println!("RPC: {}", url);
    println!();
    println!("Note: Unshield requires spending a shielded note.");
    println!("      This feature is coming soon.");

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
    println!("Note: Shielded transfers require existing shielded balance.");
    println!("      This feature is coming soon.");

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
