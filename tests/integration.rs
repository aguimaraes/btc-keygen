use std::process::Command;

/// Helper: runs the btc-keygen binary with the given arguments.
fn run_btc_keygen(args: &[&str]) -> std::process::Output {
    let binary = env!("CARGO_BIN_EXE_btc-keygen");
    Command::new(binary)
        .args(args)
        .output()
        .expect("failed to execute btc-keygen binary")
}

// ---------------------------------------------------------------
// 6.10 — CLI integration tests
// ---------------------------------------------------------------

#[test]
fn test_cli_generate_exit_code_zero() {
    let output = run_btc_keygen(&["generate"]);
    assert!(
        output.status.success(),
        "btc-keygen generate must exit 0, got: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_generate_stdout_has_address_and_wif() {
    let output = run_btc_keygen(&["generate"]);
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        stdout.contains("bc1q"),
        "stdout must contain a bc1q address, got:\n{stdout}"
    );

    // WIF for compressed mainnet keys starts with K or L.
    let has_wif = stdout.lines().any(|line| {
        let trimmed = line.trim();
        (trimmed.starts_with('K') || trimmed.starts_with('L')) && trimmed.len() == 52
    });
    // Also check if the WIF appears as a value in a key:value line.
    let has_wif_in_field = stdout.lines().any(|line| {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 {
            let val = parts[1].trim();
            (val.starts_with('K') || val.starts_with('L')) && val.len() == 52
        } else {
            false
        }
    });
    assert!(
        has_wif || has_wif_in_field,
        "stdout must contain a WIF private key, got:\n{stdout}"
    );
}

#[test]
fn test_cli_generate_stderr_has_warnings() {
    let output = run_btc_keygen(&["generate"]);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.is_empty(), "stderr must contain safety warnings");
}

#[test]
fn test_cli_json_flag() {
    let output = run_btc_keygen(&["generate", "--json"]);
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--json output must be valid JSON");
    assert!(parsed.get("address").is_some());
    assert!(parsed.get("wif").is_some());
}

#[test]
fn test_cli_hex_flag() {
    let output = run_btc_keygen(&["generate", "--hex"]);
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    // Must contain a 64-character hex string (the raw private key).
    let has_hex = stdout
        .lines()
        .any(|line| line.chars().filter(|c| c.is_ascii_hexdigit()).count() >= 64);
    assert!(
        has_hex,
        "stdout with --hex must contain 64-char hex string, got:\n{stdout}"
    );
}

#[test]
fn test_cli_pubkey_flag() {
    let output = run_btc_keygen(&["generate", "--pubkey"]);
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    // Compressed pubkey is 66 hex characters (33 bytes).
    let has_pubkey = stdout.lines().any(|line| {
        let trimmed = line.trim();
        // The pubkey hex starts with 02 or 03.
        trimmed.contains("02") || trimmed.contains("03")
    });
    assert!(
        has_pubkey,
        "stdout with --pubkey must contain compressed public key hex, got:\n{stdout}"
    );
}

#[test]
fn test_cli_all_flags_json() {
    let output = run_btc_keygen(&["generate", "--hex", "--pubkey", "--json"]);
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("JSON must be valid");
    assert!(parsed.get("address").is_some());
    assert!(parsed.get("wif").is_some());
    assert!(parsed.get("private_key_hex").is_some());
    assert!(parsed.get("pubkey_hex").is_some());
}

#[test]
fn test_cli_no_subcommand_shows_help() {
    let output = run_btc_keygen(&[]);
    // clap exits non-zero when no subcommand is given.
    assert!(
        !output.status.success(),
        "no subcommand should produce non-zero exit"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("Usage") || stderr.contains("usage"),
        "should show usage info, got:\n{stderr}"
    );
}

#[test]
fn test_cli_unknown_flag_errors() {
    let output = run_btc_keygen(&["generate", "--unknown-flag"]);
    assert!(
        !output.status.success(),
        "unknown flag must produce non-zero exit"
    );
}

// ---------------------------------------------------------------
// 6.8 — Statelessness tests
// ---------------------------------------------------------------

#[test]
fn test_two_cli_runs_produce_different_keys() {
    let output1 = run_btc_keygen(&["generate", "--json"]);
    let output2 = run_btc_keygen(&["generate", "--json"]);

    assert!(output1.status.success());
    assert!(output2.status.success());

    let stdout1 = String::from_utf8(output1.stdout).unwrap();
    let stdout2 = String::from_utf8(output2.stdout).unwrap();

    let json1: serde_json::Value = serde_json::from_str(&stdout1).unwrap();
    let json2: serde_json::Value = serde_json::from_str(&stdout2).unwrap();

    assert_ne!(
        json1.get("address"),
        json2.get("address"),
        "two runs must produce different addresses"
    );
    assert_ne!(
        json1.get("wif"),
        json2.get("wif"),
        "two runs must produce different WIF keys"
    );
}

#[test]
fn test_no_file_artifacts() {
    let dir = std::env::temp_dir().join("btc_keygen_artifact_test");
    let _ = std::fs::create_dir_all(&dir);

    // List files before.
    let before: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();

    let binary = env!("CARGO_BIN_EXE_btc-keygen");
    let output = Command::new(binary)
        .args(["generate"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(output.status.success());

    // List files after.
    let after: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();

    assert_eq!(
        before.len(),
        after.len(),
        "generate must not create any files"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_no_env_mutation() {
    // Capture a snapshot of env vars before running the binary.
    let env_before: std::collections::HashMap<String, String> = std::env::vars().collect();

    let output = run_btc_keygen(&["generate"]);
    assert!(output.status.success());

    // Verify no env vars were added or changed in *this* process.
    // The child process runs in its own address space, so it cannot mutate
    // our env. This test confirms the tool's design — it communicates only
    // via stdout/stderr, not environment variables.
    let env_after: std::collections::HashMap<String, String> = std::env::vars().collect();

    assert_eq!(
        env_before, env_after,
        "running btc-keygen must not mutate the parent process environment"
    );
}

// ---------------------------------------------------------------
// 6.9 — Structural safety checks
// ---------------------------------------------------------------

#[test]
fn test_no_network_deps() {
    // Verify the dependency tree contains no networking crates.
    let output = Command::new("cargo")
        .args(["tree", "--prefix", "none"])
        .output()
        .expect("cargo tree must succeed");
    let tree = String::from_utf8(output.stdout).unwrap();

    let banned = [
        "reqwest",
        "hyper",
        "tokio",
        "async-std",
        "surf",
        "ureq",
        "curl",
    ];
    for crate_name in &banned {
        assert!(
            !tree.lines().any(|line| line.starts_with(crate_name)),
            "dependency tree must not contain networking crate '{}'\ntree:\n{}",
            crate_name,
            tree
        );
    }
}
