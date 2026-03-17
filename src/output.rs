use std::io::{self, Write};

/// The set of values produced by a key generation run.
pub struct KeypairOutput {
    pub address: String,
    pub wif: String,
    pub private_key_hex: Option<String>,
    pub pubkey_hex: Option<String>,
}

/// Output format selection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Plain,
    Json,
}

/// Writes keypair output to stdout and safety warnings to stderr.
///
/// Returns `io::Result` so callers can handle write failures.
pub fn print_output(keypair: &KeypairOutput, format: Format) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    format_output(&mut handle, keypair, format)
}

/// Writes safety warnings to stderr.
///
/// These warnings explain the one-time nature of the generated keypair
/// and that the secret cannot be recovered after the process exits.
pub fn print_warnings(stderr: &mut dyn Write) -> io::Result<()> {
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

/// Formats keypair output to a writer (for testability without capturing stdout).
pub fn format_output(
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

    // ---------------------------------------------------------------
    // 6.7 — Output contract tests
    // ---------------------------------------------------------------

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
        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("JSON output must be valid JSON");
        assert!(parsed.is_object());
    }

    #[test]
    fn test_json_contains_address_and_wif_fields() {
        let mut buf = Vec::new();
        let kp = sample_keypair();
        format_output(&mut buf, &kp, Format::Json).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(
            parsed.get("address").is_some(),
            "JSON must have 'address' field"
        );
        assert!(parsed.get("wif").is_some(), "JSON must have 'wif' field");
    }

    #[test]
    fn test_json_all_fields_when_present() {
        let mut buf = Vec::new();
        let kp = sample_keypair_all_fields();
        format_output(&mut buf, &kp, Format::Json).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.get("address").is_some());
        assert!(parsed.get("wif").is_some());
        assert!(parsed.get("private_key_hex").is_some());
        assert!(parsed.get("pubkey_hex").is_some());
    }

    #[test]
    fn test_json_omits_optional_fields_when_absent() {
        let mut buf = Vec::new();
        let kp = sample_keypair();
        format_output(&mut buf, &kp, Format::Json).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(
            parsed.get("private_key_hex").is_none(),
            "JSON must omit private_key_hex when not requested"
        );
        assert!(
            parsed.get("pubkey_hex").is_none(),
            "JSON must omit pubkey_hex when not requested"
        );
    }

    // ---------------------------------------------------------------
    // Warning output tests
    // ---------------------------------------------------------------

    #[test]
    fn test_warnings_contain_key_safety_messages() {
        let mut buf = Vec::new();
        print_warnings(&mut buf).unwrap();
        let warnings = String::from_utf8(buf).unwrap();

        // Must mention that secrets are not stored.
        assert!(
            warnings.to_lowercase().contains("not store")
                || warnings.to_lowercase().contains("does not save"),
            "warnings must state that secrets are not stored"
        );

        // Must mention that re-running generates a new keypair.
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
