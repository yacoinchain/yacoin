//! YaCoin Test Validator
//!
//! A local development validator with shielded transaction support.
//! Based on Solana's test-validator with YaCoin privacy extensions.
//!
//! Usage:
//!   yacoin-test-validator --reset
//!
//! The validator will start on:
//!   - RPC: http://127.0.0.1:8899
//!   - WebSocket: ws://127.0.0.1:8900
//!   - Faucet: http://127.0.0.1:9900

use {
    clap::{App, Arg},
    crossbeam_channel::unbounded,
    log::*,
    solana_account::AccountSharedData,
    solana_clap_utils::input_parsers::pubkey_of,
    solana_faucet::faucet::{run_faucet, Faucet},
    solana_keypair::{read_keypair_file, write_keypair_file, Keypair},
    solana_native_token::sol_str_to_lamports,
    solana_net_utils::SocketAddrSpace,
    solana_pubkey::Pubkey,
    solana_rpc::rpc::JsonRpcConfig,
    solana_signer::Signer,
    solana_system_interface::program as system_program,
    solana_test_validator::*,
    std::{
        env, fs,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::PathBuf,
        process::exit,
        sync::{Arc, Mutex},
        thread,
    },
};

#[cfg(not(any(target_env = "msvc", target_os = "freebsd")))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

/// YaCoin Shielded Transfer Program ID
/// This is the program that handles all shielded transactions
pub const SHIELDED_TRANSFER_PROGRAM_ID: &str = "YaCoin1111111111111111111111111111111111111";

fn main() {
    // Enable backtraces for debugging
    if env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { env::set_var("RUST_BACKTRACE", "1") }
    }

    let version = solana_version::version!();
    let matches = App::new("yacoin-test-validator")
        .version(version)
        .author("YaCoin Team")
        .about("YaCoin Test Validator - Local development node with shielded transactions")
        .arg(
            Arg::with_name("ledger_path")
                .short("l")
                .long("ledger")
                .value_name("DIR")
                .takes_value(true)
                .default_value("test-ledger")
                .help("Use DIR as ledger location"),
        )
        .arg(
            Arg::with_name("reset")
                .short("r")
                .long("reset")
                .takes_value(false)
                .help("Reset the ledger to genesis"),
        )
        .arg(
            Arg::with_name("rpc_port")
                .long("rpc-port")
                .value_name("PORT")
                .takes_value(true)
                .default_value("8899")
                .help("JSON RPC port for the validator"),
        )
        .arg(
            Arg::with_name("faucet_port")
                .long("faucet-port")
                .value_name("PORT")
                .takes_value(true)
                .default_value("9900")
                .help("Faucet port"),
        )
        .arg(
            Arg::with_name("faucet_sol")
                .long("faucet-sol")
                .value_name("SOL")
                .takes_value(true)
                .default_value("1000000")
                .help("Amount of SOL to give to the faucet"),
        )
        .arg(
            Arg::with_name("mint_address")
                .long("mint")
                .value_name("PUBKEY")
                .takes_value(true)
                .help("Address to mint initial tokens to"),
        )
        .arg(
            Arg::with_name("quiet")
                .short("q")
                .long("quiet")
                .takes_value(false)
                .help("Suppress output"),
        )
        .get_matches();

    // Initialize logging
    if !matches.is_present("quiet") {
        agave_logger::setup();
    }

    println!();
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║           YaCoin Test Validator v{}                    ║", version);
    println!("║       Local development node with shielded transactions       ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();

    let ledger_path: PathBuf = matches.value_of("ledger_path").unwrap().into();
    let reset_ledger = matches.is_present("reset");
    let rpc_port: u16 = matches.value_of("rpc_port").unwrap().parse().unwrap();
    let faucet_port: u16 = matches.value_of("faucet_port").unwrap().parse().unwrap();

    // Create ledger directory if needed
    if !ledger_path.exists() {
        fs::create_dir_all(&ledger_path).unwrap_or_else(|err| {
            eprintln!("Error: Unable to create directory {}: {}", ledger_path.display(), err);
            exit(1);
        });
    }

    // Reset ledger if requested
    if reset_ledger && ledger_path.exists() {
        println!("Resetting ledger...");
        for entry in fs::read_dir(&ledger_path).unwrap() {
            let entry = entry.unwrap();
            if entry.metadata().unwrap().is_dir() {
                fs::remove_dir_all(entry.path()).ok();
            } else {
                fs::remove_file(entry.path()).ok();
            }
        }
    }

    // Get or create mint address
    let cli_config = solana_cli_config::Config::default();
    let mint_address = pubkey_of(&matches, "mint_address")
        .or_else(|| read_keypair_file(&cli_config.keypair_path).ok().map(|kp| kp.pubkey()))
        .unwrap_or_else(|| Keypair::new().pubkey());

    // Setup faucet
    let faucet_lamports = matches
        .value_of("faucet_sol")
        .and_then(sol_str_to_lamports)
        .unwrap_or(1_000_000_000_000_000); // 1M SOL default

    let faucet_keypair_file = ledger_path.join("faucet-keypair.json");
    if !faucet_keypair_file.exists() {
        write_keypair_file(&Keypair::new(), faucet_keypair_file.to_str().unwrap()).unwrap();
    }

    let faucet_keypair = read_keypair_file(faucet_keypair_file.to_str().unwrap()).unwrap();
    let faucet_pubkey = faucet_keypair.pubkey();

    let faucet_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), faucet_port);

    // Start faucet in background
    let (sender, receiver) = unbounded();
    thread::spawn(move || {
        let faucet = Arc::new(Mutex::new(Faucet::new(
            faucet_keypair,
            Some(3600), // 1 hour time slice
            None,
            None,
        )));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(run_faucet(faucet, faucet_addr, Some(sender)));
    });
    let _ = receiver.recv().expect("run faucet");

    // Configure genesis
    let socket_addr_space = SocketAddrSpace::new(true);

    let mut genesis = TestValidatorGenesis::default();
    genesis
        .ledger_path(&ledger_path)
        .add_account(
            faucet_pubkey,
            AccountSharedData::new(faucet_lamports, 0, &system_program::id()),
        )
        .rpc_port(rpc_port);

    genesis.rpc_config(JsonRpcConfig {
        enable_rpc_transaction_history: true,
        enable_extended_tx_metadata_storage: true,
        faucet_addr: Some(faucet_addr),
        ..JsonRpcConfig::default_for_test()
    });

    println!("Starting YaCoin Test Validator...");
    println!();
    println!("  Ledger:    {}", ledger_path.display());
    println!("  RPC URL:   http://127.0.0.1:{}", rpc_port);
    println!("  WebSocket: ws://127.0.0.1:{}", rpc_port + 1);
    println!("  Faucet:    http://127.0.0.1:{}", faucet_port);
    println!();
    println!("  Mint:      {}", mint_address);
    println!("  Faucet PK: {}", faucet_pubkey);
    println!();
    println!("YaCoin Shielded Transfer Program: {}", SHIELDED_TRANSFER_PROGRAM_ID);
    println!();
    println!("Press Ctrl+C to stop the validator");
    println!();

    // Start the validator
    match genesis.start_with_mint_address(mint_address, socket_addr_space) {
        Ok(test_validator) => {
            info!("YaCoin Test Validator started successfully");
            test_validator.join();
        }
        Err(err) => {
            eprintln!("Error: failed to start validator: {}", err);
            exit(1);
        }
    }
}
