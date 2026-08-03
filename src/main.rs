use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::process::ExitCode;

use btc_keygen::{PrivateKey, SecretKeyHex, SecretWif};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

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
        /// Import your own private key hex; use `-` to read it from stdin
        ///
        /// Passing the key as the argument value is DEPRECATED and will be
        /// removed in 0.4.0. An argument is written to your shell history and is
        /// visible to `ps` while the command runs, and neither exposure can be
        /// undone afterwards. Read the key from stdin instead:
        ///
        ///   btc-keygen generate --from-hex - < key.hex
        ///
        /// With no redirection, `-` prompts for the key when run interactively.
        #[arg(long, value_name = "HEX|-")]
        from_hex: Option<String>,

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
    wif: SecretWif,
    private_key_hex: Option<SecretKeyHex>,
    pubkey_hex: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Plain,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            from_hex,
            hex,
            pubkey,
            json,
        } => run_generate(from_hex, hex, pubkey, json),
    }
}

fn run_generate(
    from_hex: Option<String>,
    include_hex: bool,
    include_pubkey: bool,
    json: bool,
) -> ExitCode {
    let mut stderr = io::stderr().lock();
    if let Err(e) = print_warnings(&mut stderr) {
        eprintln!("failed to write warnings: {}", e);
        return ExitCode::FAILURE;
    }
    drop(stderr);

    let private_key = if let Some(source) = from_hex {
        let hex = match resolve_key_hex(source) {
            Ok(hex) => hex,
            Err(e) => {
                eprintln!("failed to read private key: {}", e);
                return ExitCode::FAILURE;
            }
        };
        match PrivateKey::from_hex(hex.trim()) {
            Ok(key) => key,
            Err(e) => {
                eprintln!("invalid private key: {}", e);
                return ExitCode::FAILURE;
            }
        }
    } else {
        match btc_keygen::generate() {
            Ok(key) => key,
            Err(e) => {
                eprintln!("key generation failed: {}", e);
                return ExitCode::FAILURE;
            }
        }
    };

    let wif = btc_keygen::encode_wif(&private_key);

    let compressed_pubkey = btc_keygen::derive_pubkey(&private_key);

    let address = btc_keygen::derive_address(&compressed_pubkey);

    let private_key_hex = if include_hex {
        Some(private_key.to_hex())
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
        wif,
        private_key_hex,
        pubkey_hex,
    };

    let format = if json { Format::Json } else { Format::Plain };

    if let Err(e) = print_output(&keypair, format) {
        eprintln!("failed to write output: {}", e);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

/// Longest key input accepted: 64 hex digits plus room for surrounding
/// whitespace and a line ending. Bounded so that a mistaken `cat` of a large
/// file is rejected instead of being read into memory.
const MAX_HEX_INPUT: usize = 128;

/// Resolves the `--from-hex` value into private key hex.
///
/// `-` reads the key from stdin, which is the only channel that keeps it out of
/// the process argument list. Any other value *is* the key, and the operator is
/// warned that it has already leaked somewhere this program cannot reach.
fn resolve_key_hex(source: String) -> io::Result<Zeroizing<String>> {
    if source != "-" {
        // Wrapped so this process at least erases its own copy. The argument
        // vector itself belongs to the kernel and cannot be erased here.
        let hex = Zeroizing::new(source);
        warn_key_on_command_line(&mut io::stderr().lock())?;
        return Ok(hex);
    }

    let mut stdin = io::stdin().lock();
    if stdin.is_terminal() {
        // Without a prompt, an interactive run is indistinguishable from a hang.
        let mut stderr = io::stderr().lock();
        write!(stderr, "private key hex: ")?;
        stderr.flush()?;
    }
    read_hex_line(&mut stdin)
}

/// Reads one line of private key hex from `reader`.
///
/// The buffer is allocated once at full capacity, so growing it cannot leave
/// half-written copies of the key on the heap, and it erases itself on drop.
///
/// # Errors
///
/// Returns an error on empty input, or on a line longer than
/// [`MAX_HEX_INPUT`]. Over-long input is rejected rather than truncated: a
/// silently shortened key would derive a different, unrecoverable address.
fn read_hex_line(reader: &mut dyn BufRead) -> io::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::with_capacity(MAX_HEX_INPUT + 1));

    // One byte past the cap, so hitting it is detectable.
    reader.take(MAX_HEX_INPUT as u64 + 1).read_line(&mut line)?;

    if line.len() > MAX_HEX_INPUT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("key input exceeds {MAX_HEX_INPUT} bytes"),
        ));
    }
    if line.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "no private key on stdin",
        ));
    }
    Ok(line)
}

fn warn_key_on_command_line(stderr: &mut dyn Write) -> io::Result<()> {
    writeln!(stderr)?;
    writeln!(
        stderr,
        "DEPRECATED: the private key was passed as a command-line argument."
    )?;
    writeln!(stderr, "This form will be removed in 0.4.0.")?;
    writeln!(stderr)?;
    writeln!(
        stderr,
        "It is now in this shell's history file, and it was visible to any"
    )?;
    writeln!(
        stderr,
        "process that ran `ps` while this command was running. Neither of"
    )?;
    writeln!(stderr, "those can be undone by this program.")?;
    writeln!(stderr)?;
    writeln!(
        stderr,
        "Read the key from stdin instead, which avoids both:"
    )?;
    writeln!(stderr, "  btc-keygen generate --from-hex - < key.hex")?;
    writeln!(stderr, "================================================")?;
    Ok(())
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

    // Secrets go out as raw bytes: `write_all` hands them to the writer without
    // routing them through the formatting machinery.
    write!(writer, "wif: ")?;
    writer.write_all(keypair.wif.expose_bytes())?;
    writeln!(writer)?;

    if let Some(hex) = &keypair.private_key_hex {
        write!(writer, "private_key_hex: ")?;
        writer.write_all(hex.expose_bytes())?;
        writeln!(writer)?;
    }
    if let Some(pk) = keypair.pubkey_hex.as_deref() {
        writeln!(writer, "pubkey_hex: {}", pk)?;
    }
    Ok(())
}

fn format_json(writer: &mut dyn Write, keypair: &KeypairOutput) -> io::Result<()> {
    write!(writer, "{{")?;
    write!(writer, "\"address\":\"{}\"", keypair.address)?;

    // Base58 and hex need no JSON escaping, so the secret bytes can be written
    // verbatim between the quotes.
    write!(writer, ",\"wif\":\"")?;
    writer.write_all(keypair.wif.expose_bytes())?;
    write!(writer, "\"")?;

    if let Some(hex) = &keypair.private_key_hex {
        write!(writer, ",\"private_key_hex\":\"")?;
        writer.write_all(hex.expose_bytes())?;
        write!(writer, "\"")?;
    }
    if let Some(pk) = keypair.pubkey_hex.as_deref() {
        write!(writer, ",\"pubkey_hex\":\"{}\"", pk)?;
    }
    writeln!(writer, "}}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Secret types cannot be cloned or built from a literal, so fixtures come
    /// from the real pipeline for the known scalar-1 test vector.
    fn sample_key() -> PrivateKey {
        PrivateKey::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap()
    }

    fn sample_keypair() -> KeypairOutput {
        KeypairOutput {
            address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            wif: btc_keygen::encode_wif(&sample_key()),
            private_key_hex: None,
            pubkey_hex: None,
        }
    }

    fn sample_keypair_all_fields() -> KeypairOutput {
        let key = sample_key();
        KeypairOutput {
            address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            wif: btc_keygen::encode_wif(&key),
            private_key_hex: Some(key.to_hex()),
            pubkey_hex: Some(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
            ),
        }
    }

    #[test]
    fn test_debug_of_output_secrets_is_redacted() {
        let kp = sample_keypair_all_fields();
        let debug = format!("{:?} {:?}", kp.wif, kp.private_key_hex);
        assert!(
            !debug.contains("KwDi") && !debug.contains("000000"),
            "Debug must not leak secrets, got: {debug}"
        );
    }

    #[test]
    fn test_read_hex_line_accepts_plain_line() {
        let input = b"0000000000000000000000000000000000000000000000000000000000000001\n";
        let hex = read_hex_line(&mut &input[..]).unwrap();
        assert_eq!(hex.trim().len(), 64);
        assert!(PrivateKey::from_hex(hex.trim()).is_ok());
    }

    #[test]
    fn test_read_hex_line_tolerates_crlf_and_spaces() {
        let input = b"  0000000000000000000000000000000000000000000000000000000000000001  \r\n";
        let hex = read_hex_line(&mut &input[..]).unwrap();
        assert!(PrivateKey::from_hex(hex.trim()).is_ok());
    }

    #[test]
    fn test_read_hex_line_accepts_missing_trailing_newline() {
        let input = b"0000000000000000000000000000000000000000000000000000000000000001";
        let hex = read_hex_line(&mut &input[..]).unwrap();
        assert!(PrivateKey::from_hex(hex.trim()).is_ok());
    }

    #[test]
    fn test_read_hex_line_reads_only_the_first_line() {
        let input =
            b"0000000000000000000000000000000000000000000000000000000000000001\ntrailing junk\n";
        let hex = read_hex_line(&mut &input[..]).unwrap();
        assert!(PrivateKey::from_hex(hex.trim()).is_ok());
    }

    #[test]
    fn test_read_hex_line_rejects_empty_input() {
        assert!(
            read_hex_line(&mut &b""[..]).is_err(),
            "empty stdin must error"
        );
        assert!(
            read_hex_line(&mut &b"\n"[..]).is_err(),
            "a bare newline must error"
        );
    }

    #[test]
    fn test_read_hex_line_rejects_overlong_input_instead_of_truncating() {
        let input = [b'0'; MAX_HEX_INPUT + 10];
        let err = read_hex_line(&mut &input[..]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_warning_names_the_stdin_alternative() {
        let mut buf = Vec::new();
        warn_key_on_command_line(&mut buf).unwrap();
        let warning = String::from_utf8(buf).unwrap();
        assert!(warning.contains("--from-hex -"));
        assert!(warning.to_lowercase().contains("history"));
    }

    /// A deprecation notice with no removal version never gets removed.
    #[test]
    fn test_warning_states_deprecation_and_removal_version() {
        let mut buf = Vec::new();
        warn_key_on_command_line(&mut buf).unwrap();
        let warning = String::from_utf8(buf).unwrap();
        assert!(
            warning.contains("DEPRECATED"),
            "the warning must say the form is deprecated, got:\n{warning}"
        );
        assert!(
            warning.contains("0.4.0"),
            "the warning must name the removal version, got:\n{warning}"
        );
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
