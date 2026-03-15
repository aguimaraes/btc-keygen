use std::process;

use clap::{Parser, Subcommand};

use btc_keygen::address;
use btc_keygen::entropy::OsEntropy;
use btc_keygen::keygen;
use btc_keygen::output::{self, Format, KeypairOutput};
use btc_keygen::pubkey;
use btc_keygen::wif;

#[derive(Parser)]
#[command(name = "btc-keygen")]
#[command(about = "Minimal offline Bitcoin key generator for cold storage")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Bitcoin keypair
    Generate {
        /// Include raw private key in hexadecimal
        #[arg(long)]
        hex: bool,

        /// Include compressed public key in hexadecimal
        #[arg(long)]
        pubkey: bool,

        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { hex, pubkey, json } => {
            run_generate(hex, pubkey, json);
        }
    }
}

fn run_generate(include_hex: bool, include_pubkey: bool, json: bool) {
    // Print safety warnings to stderr.
    let mut stderr = std::io::stderr().lock();
    if let Err(e) = output::print_warnings(&mut stderr) {
        eprintln!("failed to write warnings: {}", e);
        process::exit(1);
    }
    drop(stderr);

    // Generate private key from OS entropy.
    let private_key = match keygen::generate(&OsEntropy) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("key generation failed: {}", e);
            process::exit(1);
        }
    };

    // Derive WIF.
    let wif_str = wif::encode_wif(private_key.as_bytes());

    // Derive compressed public key.
    let secret_key = private_key.to_secret_key();
    let compressed_pubkey = pubkey::derive_pubkey(&secret_key);

    // Derive address.
    let address = address::derive_address(&compressed_pubkey);

    // Build output.
    let private_key_hex = if include_hex {
        Some(
            private_key
                .as_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect(),
        )
    } else {
        None
    };

    let pubkey_hex = if include_pubkey {
        Some(
            compressed_pubkey
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect(),
        )
    } else {
        None
    };

    let keypair = KeypairOutput {
        address,
        wif: wif_str,
        private_key_hex,
        pubkey_hex,
    };

    let format = if json { Format::Json } else { Format::Plain };

    if let Err(e) = output::print_output(&keypair, format) {
        eprintln!("failed to write output: {}", e);
        process::exit(1);
    }

    // private_key is dropped here — ZeroizeOnDrop clears the bytes.
}
