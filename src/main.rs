use std::io::{self, Write};
use std::process;

use clap::{Parser, Subcommand};

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

struct KeypairOutput {
    address: String,
    wif: String,
    private_key_hex: Option<String>,
    pubkey_hex: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Plain,
    Json,
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
    let mut stderr = io::stderr().lock();
    if let Err(e) = print_warnings(&mut stderr) {
        eprintln!("failed to write warnings: {}", e);
        process::exit(1);
    }
    drop(stderr);

    // Generate private key from OS entropy.
    let private_key = match btc_keygen::generate() {
        Ok(key) => key,
        Err(e) => {
            eprintln!("key generation failed: {}", e);
            process::exit(1);
        }
    };

    // Derive WIF.
    let wif_str = btc_keygen::encode_wif(&private_key);

    // Derive compressed public key.
    let compressed_pubkey = btc_keygen::derive_pubkey(&private_key);

    // Derive address.
    let address = btc_keygen::derive_address(&compressed_pubkey);

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

    if let Err(e) = print_output(&keypair, format) {
        eprintln!("failed to write output: {}", e);
        process::exit(1);
    }

    // private_key is dropped here — ZeroizeOnDrop clears the bytes.
}

fn print_output(keypair: &KeypairOutput, format: Format) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    format_output(&mut handle, keypair, format)
}

fn print_warnings(stderr: &mut dyn Write) -> io::Result<()> {
    writeln!(stderr, "=== btc-keygen: one-time key generation ===")?;
    writeln!(stderr)?;
    writeln!(
        stderr,
        "The address and private key printed below belong together."
    )?;
    writeln!(
        stderr,
        "The private key is required to spend funds sent to this address."
    )?;
    writeln!(stderr)?;
    writeln!(stderr, "This tool does not save or store any secrets.")?;
    writeln!(
        stderr,
        "If you lose the private key output, funds sent to this address"
    )?;
    writeln!(stderr, "may be permanently inaccessible.")?;
    writeln!(stderr)?;
    writeln!(
        stderr,
        "Re-running this tool generates a new, different keypair."
    )?;
    writeln!(stderr, "It does NOT recover a previously generated key.")?;
    writeln!(stderr, "================================================")?;
    Ok(())
}

fn format_output(
    writer: &mut dyn Write,
    keypair: &KeypairOutput,
    format: Format,
) -> io::Result<()> {
    match format {
        Format::Plain => format_plain(writer, keypair),
        Format::Json => format_json(writer, keypair),
    }
}

fn format_plain(writer: &mut dyn Write, keypair: &KeypairOutput) -> io::Result<()> {
    writeln!(writer, "address: {}", keypair.address)?;
    writeln!(writer, "wif: {}", keypair.wif)?;
    if let Some(ref hex) = keypair.private_key_hex {
        writeln!(writer, "private_key_hex: {}", hex)?;
    }
    if let Some(ref pk) = keypair.pubkey_hex {
        writeln!(writer, "pubkey_hex: {}", pk)?;
    }
    Ok(())
}

fn format_json(writer: &mut dyn Write, keypair: &KeypairOutput) -> io::Result<()> {
    write!(writer, "{{")?;
    write!(writer, "\"address\":\"{}\"", keypair.address)?;
    write!(writer, ",\"wif\":\"{}\"", keypair.wif)?;
    if let Some(ref hex) = keypair.private_key_hex {
        write!(writer, ",\"private_key_hex\":\"{}\"", hex)?;
    }
    if let Some(ref pk) = keypair.pubkey_hex {
        write!(writer, ",\"pubkey_hex\":\"{}\"", pk)?;
    }
    writeln!(writer, "}}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_keypair() -> KeypairOutput {
        KeypairOutput {
            address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            wif: "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn".into(),
            private_key_hex: None,
            pubkey_hex: None,
        }
    }

    fn sample_keypair_all_fields() -> KeypairOutput {
        KeypairOutput {
            address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            wif: "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn".into(),
            private_key_hex: Some(
                "0000000000000000000000000000000000000000000000000000000000000001".into(),
            ),
            pubkey_hex: Some(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
            ),
        }
    }

    #[test]
    fn test_plain_output_contains_address() {
        let mut buf = Vec::new();
        let kp = sample_keypair();
        format_output(&mut buf, &kp, Format::Plain).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("bc1q"), "plain output must contain address");
    }

    #[test]
    fn test_plain_output_contains_wif() {
        let mut buf = Vec::new();
        let kp = sample_keypair();
        format_output(&mut buf, &kp, Format::Plain).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
            "plain output must contain WIF"
        );
    }

    #[test]
    fn test_plain_output_both_address_and_wif() {
        let mut buf = Vec::new();
        let kp = sample_keypair();
        format_output(&mut buf, &kp, Format::Plain).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("bc1q"));
        assert!(output.contains("KwDiBf89"));
    }

    #[test]
    fn test_hex_included_when_present() {
        let mut buf = Vec::new();
        let kp = sample_keypair_all_fields();
        format_output(&mut buf, &kp, Format::Plain).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("0000000000000000000000000000000000000000000000000000000000000001"),
            "output must include hex when field is Some"
        );
    }

    #[test]
    fn test_pubkey_included_when_present() {
        let mut buf = Vec::new();
        let kp = sample_keypair_all_fields();
        format_output(&mut buf, &kp, Format::Plain).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
            "output must include pubkey hex when field is Some"
        );
    }

    #[test]
    fn test_json_output_is_valid_json() {
        let mut buf = Vec::new();
        let kp = sample_keypair();
        format_output(&mut buf, &kp, Format::Json).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with('{'), "JSON must start with {{");
        assert!(output.trim().ends_with('}'), "JSON must end with }}");
    }

    #[test]
    fn test_json_contains_address_and_wif_fields() {
        let mut buf = Vec::new();
        let kp = sample_keypair();
        format_output(&mut buf, &kp, Format::Json).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("\"address\""),
            "JSON must have 'address' field"
        );
        assert!(output.contains("\"wif\""), "JSON must have 'wif' field");
    }

    #[test]
    fn test_json_all_fields_when_present() {
        let mut buf = Vec::new();
        let kp = sample_keypair_all_fields();
        format_output(&mut buf, &kp, Format::Json).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("\"address\""));
        assert!(output.contains("\"wif\""));
        assert!(output.contains("\"private_key_hex\""));
        assert!(output.contains("\"pubkey_hex\""));
    }

    #[test]
    fn test_json_omits_optional_fields_when_absent() {
        let mut buf = Vec::new();
        let kp = sample_keypair();
        format_output(&mut buf, &kp, Format::Json).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            !output.contains("\"private_key_hex\""),
            "JSON must omit private_key_hex when not requested"
        );
        assert!(
            !output.contains("\"pubkey_hex\""),
            "JSON must omit pubkey_hex when not requested"
        );
    }

    #[test]
    fn test_warnings_contain_key_safety_messages() {
        let mut buf = Vec::new();
        print_warnings(&mut buf).unwrap();
        let warnings = String::from_utf8(buf).unwrap();

        assert!(
            warnings.to_lowercase().contains("not store")
                || warnings.to_lowercase().contains("does not save"),
            "warnings must state that secrets are not stored"
        );

        assert!(
            warnings.to_lowercase().contains("new keypair")
                || warnings.to_lowercase().contains("different"),
            "warnings must state re-running creates a new keypair"
        );
    }

    #[test]
    fn test_plain_output_does_not_contain_warnings() {
        let mut buf = Vec::new();
        let kp = sample_keypair();
        format_output(&mut buf, &kp, Format::Plain).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            !output.to_lowercase().contains("warning"),
            "stdout (format_output) must not contain warning text"
        );
    }
}
