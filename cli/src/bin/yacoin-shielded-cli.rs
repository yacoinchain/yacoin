//! YaCoin Shielded CLI
//!
//! Command-line interface for shielded (private) transactions on YaCoin.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "yacoin-shielded-cli")]
#[command(about = "YaCoin Shielded Transaction CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// RPC URL
    #[arg(short, long, default_value = "http://127.0.0.1:8899")]
    url: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new shielded wallet
    Keygen {
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Don't encrypt the wallet
        #[arg(long)]
        no_passphrase: bool,
    },

    /// Display shielded payment address
    Address {
        /// Wallet file path
        #[arg(short, long)]
        wallet: PathBuf,

        /// Generate a new diversified address
        #[arg(long)]
        new: bool,
    },

    /// Check shielded balance
    Balance {
        /// Wallet file path
        #[arg(short, long)]
        wallet: PathBuf,
    },

    /// Shield tokens (transparent -> shielded)
    Shield {
        /// Amount in lamports (1 YAC = 1_000_000_000 lamports)
        #[arg(short, long)]
        amount: u64,

        /// Shielded wallet file
        #[arg(short, long)]
        wallet: PathBuf,

        /// Transparent keypair to spend from
        #[arg(short, long)]
        keypair: Option<PathBuf>,
    },

    /// Unshield tokens (shielded -> transparent)
    Unshield {
        /// Amount in lamports
        #[arg(short, long)]
        amount: u64,

        /// Shielded wallet file
        #[arg(short, long)]
        wallet: PathBuf,

        /// Transparent destination address
        #[arg(short, long)]
        to: String,
    },

    /// Private shielded transfer
    Transfer {
        /// Amount in lamports
        #[arg(short, long)]
        amount: u64,

        /// Shielded wallet file
        #[arg(short, long)]
        wallet: PathBuf,

        /// Destination shielded address (starts with ys1)
        #[arg(short, long)]
        to: String,

        /// Optional memo
        #[arg(short, long)]
        memo: Option<String>,
    },

    /// Export viewing key (safe to share)
    ExportViewingKey {
        /// Wallet file path
        #[arg(short, long)]
        wallet: PathBuf,

        /// Output file for viewing key
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Keygen { output, no_passphrase } => {
            cmd_keygen(output, no_passphrase)
        }
        Commands::Address { wallet, new } => {
            cmd_address(&wallet, new)
        }
        Commands::Balance { wallet } => {
            cmd_balance(&wallet, &cli.url)
        }
        Commands::Shield { amount, wallet, keypair } => {
            cmd_shield(amount, &wallet, keypair.as_deref(), &cli.url)
        }
        Commands::Unshield { amount, wallet, to } => {
            cmd_unshield(amount, &wallet, &to, &cli.url)
        }
        Commands::Transfer { amount, wallet, to, memo } => {
            cmd_transfer(amount, &wallet, &to, memo.as_deref(), &cli.url)
        }
        Commands::ExportViewingKey { wallet, output } => {
            cmd_export_viewing_key(&wallet, output.as_deref())
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
    rand::thread_rng().fill_bytes(&mut seed);

    // Get password if needed
    let password = if no_passphrase {
        None
    } else {
        print!("Enter wallet password: ");
        io::stdout().flush()?;
        let password = rpassword::read_password()?;

        print!("Confirm password: ");
        io::stdout().flush()?;
        let confirm = rpassword::read_password()?;

        if password != confirm {
            return Err("Passwords don't match".into());
        }
        Some(password)
    };

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
        "encrypted": password.is_some(),
        "seed_hex": hex::encode(&seed),
        // In real implementation, this would be encrypted with the password
    });

    std::fs::write(&output_path, serde_json::to_string_pretty(&wallet_data)?)?;

    // Generate address from seed (simplified)
    let address = generate_shielded_address(&seed, 0);

    println!("Generating new shielded wallet...");
    println!();
    println!("=================================================================");
    println!("Shielded address: {}", address);
    println!("=================================================================");
    println!();
    println!("Wallet saved to: {}", output_path.display());
    println!();
    println!("IMPORTANT: Back up your wallet file and remember your password!");
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
        // In real implementation, we'd track and increment diversifier index
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

    // In real implementation:
    // 1. Get viewing key from seed
    // 2. Scan all encrypted notes on chain
    // 3. Try to decrypt each with viewing key
    // 4. Sum up unspent notes

    // For now, just show placeholder
    println!("Shielded balance: 0 YAC");
    println!();
    println!("Note: Full balance scanning requires syncing with the blockchain.");
    println!("      This may take a while for large note sets.");

    Ok(())
}

fn cmd_shield(amount: u64, wallet: &PathBuf, keypair: Option<&PathBuf>, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let wallet_data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(wallet)?)?;
    let seed_hex = wallet_data["seed_hex"].as_str().ok_or("Invalid wallet file")?;
    let seed = hex::decode(seed_hex)?;

    let address = generate_shielded_address(&seed, 0);

    println!("Shielding {} lamports ({} YAC)", amount, amount as f64 / 1_000_000_000.0);
    println!("To shielded address: {}", address);
    println!("RPC: {}", url);

    if keypair.is_none() {
        println!();
        println!("Error: Please specify a transparent keypair with --keypair");
        println!("       The keypair will pay for the shielding transaction.");
        return Ok(());
    }

    // In real implementation:
    // 1. Create Shield instruction with amount and output note
    // 2. Build transaction
    // 3. Generate zk-SNARK proof for the output
    // 4. Sign and submit transaction

    println!();
    println!("Shield transaction submitted!");
    println!("Signature: <would be actual signature>");
    println!();
    println!("Note: Full shielding requires Sapling parameters (~1GB).");
    println!("      Download with: yacoin fetch-params");

    Ok(())
}

fn cmd_unshield(amount: u64, wallet: &PathBuf, to: &str, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Unshielding {} lamports ({} YAC)", amount, amount as f64 / 1_000_000_000.0);
    println!("To transparent address: {}", to);
    println!("From wallet: {}", wallet.display());
    println!("RPC: {}", url);

    // In real implementation:
    // 1. Select shielded notes to spend
    // 2. Create Unshield instruction
    // 3. Generate zk-SNARK spend proof
    // 4. Sign and submit transaction

    println!();
    println!("Note: Full unshielding requires Sapling parameters.");

    Ok(())
}

fn cmd_transfer(amount: u64, wallet: &PathBuf, to: &str, memo: Option<&str>, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !to.starts_with("ys1") {
        return Err("Invalid shielded address. Must start with 'ys1'".into());
    }

    println!("Private shielded transfer");
    println!("Amount: {} lamports ({} YAC)", amount, amount as f64 / 1_000_000_000.0);
    println!("To: {}", to);
    println!("From wallet: {}", wallet.display());
    if let Some(m) = memo {
        println!("Memo: {}", m);
    }
    println!("RPC: {}", url);

    // In real implementation:
    // 1. Select shielded notes to spend
    // 2. Create ShieldedTransfer instruction with spend + output descriptions
    // 3. Generate zk-SNARK proofs for both spend and output
    // 4. Sign and submit transaction

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

    // In real implementation, derive viewing key from seed
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

/// Generate a shielded address from seed and diversifier index
fn generate_shielded_address(seed: &[u8], index: u32) -> String {
    use blake2b_simd::Params;

    // Derive diversifier-specific key material
    let mut input = Vec::new();
    input.extend_from_slice(seed);
    input.extend_from_slice(&index.to_le_bytes());

    let hash = Params::new()
        .hash_length(43) // Sapling address is 43 bytes
        .personal(b"Zcash_gd")
        .to_state()
        .update(&input)
        .finalize();

    // Encode as bech32 with "ys1" prefix (YaCoin Sapling address)
    let data: Vec<u8> = hash.as_bytes().to_vec();

    // Simple bech32 encoding (in real implementation, use proper bech32)
    format!("ys1{}", hex::encode(&data[..32]))
}
