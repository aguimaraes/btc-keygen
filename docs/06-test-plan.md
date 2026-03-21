# Test Plan

## Testing strategy

All tests are written in Rust. Tests are written before implementation (TDD).

Randomness is testable via the `EntropySource` trait. Unit tests use
`FixedEntropy` for deterministic results. Integration tests use `OsEntropy`
implicitly and verify structural properties (format, length, prefix) rather
than exact values.

No test depends on the internet or any external service.

## 6.0 — Entropy source self-tests

Module: `entropy`

Tests for the test infrastructure itself — verifying that `FixedEntropy` and
`FailingEntropy` behave correctly before using them in downstream tests.

| Test | Description |
|---|---|
| `test_fixed_entropy_fills_exact_bytes` | `FixedEntropy` fills a buffer with the exact provided bytes |
| `test_fixed_entropy_sequential_chunks` | Two consecutive `fill_bytes` calls return sequential 32-byte chunks |
| `test_fixed_entropy_exhausted_returns_error` | Requesting more bytes than available returns an error |
| `test_failing_entropy_always_errors` | `FailingEntropy` always returns an error |

## 6.1 — Private key boundary validation

Module: `keygen`

| Test | Input | Expected result |
|---|---|---|
| `test_zero_key_rejected` | 32 zero bytes | Rejected (0 is not a valid scalar) |
| `test_one_key_valid` | `0x00...01` (scalar = 1) | Accepted |
| `test_curve_order_minus_one_valid` | `n - 1` bytes | Accepted (maximum valid scalar) |
| `test_curve_order_rejected` | `n` bytes (exact curve order) | Rejected |
| `test_curve_order_plus_one_rejected` | `n + 1` bytes | Rejected |
| `test_all_ff_rejected` | 32 `0xFF` bytes | Rejected (exceeds curve order) |
| `test_valid_midrange_key` | Known 32-byte value in valid range | Accepted |

## 6.2 — Deterministic key generation with injectable entropy

Module: `keygen`

| Test | Description |
|---|---|
| `test_fixed_entropy_produces_expected_key` | `FixedEntropy` with known 32 bytes produces exact expected private key bytes |
| `test_different_entropy_produces_different_keys` | Two `FixedEntropy` sources with different bytes produce distinct keys |
| `test_same_entropy_produces_same_key` | Same `FixedEntropy` used twice produces same key (deterministic) |
| `test_invalid_entropy_triggers_retry` | `FixedEntropy` yields curve order `n` (invalid) on first call, then valid bytes on second call; generation succeeds |
| `test_entropy_failure_propagates` | `FailingEntropy` returns error; `generate_with_entropy()` propagates it |
| `test_generated_key_converts_to_secret_key` | Generated key can be converted to `secp256k1::SecretKey` without panic |

## 6.3 — WIF encoding

Module: `wif`

Known-answer tests using published Bitcoin test vectors. Tests construct a
`PrivateKey` via `PrivateKey::from_bytes()` and pass it to `encode_wif()`.

| Test | Input (hex private key) | Expected WIF |
|---|---|---|
| `test_wif_vector_scalar_one` | `0000000000000000000000000000000000000000000000000000000000000001` | `KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn` |
| `test_wif_vector_two` | `0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D` | `KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617` |
| `test_wif_starts_with_k_or_l` | Multiple valid compressed mainnet keys | WIF starts with `K` or `L` |
| `test_wif_length_52` | Any valid key | WIF is 52 characters |
| `test_wif_valid_base58_characters` | Any valid key | All characters in Base58 alphabet |
| `test_wif_checksum_valid` | Encode, Base58-decode, verify last 4 bytes match double-SHA256 of payload; verify payload structure (0x80 prefix, key bytes, 0x01 compression flag) |

## 6.4 — Compressed public key derivation

Module: `pubkey`

Tests construct a `PrivateKey` via `PrivateKey::from_bytes()` and pass it to
`derive_pubkey()`.

| Test | Input (private key hex) | Expected compressed pubkey hex |
|---|---|---|
| `test_pubkey_vector_generator_point` | `0x01` (scalar = 1) | `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` (generator point G) |
| `test_pubkey_vector_scalar_two` | `0x02` (scalar = 2) | `02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5` |
| `test_pubkey_starts_with_02_or_03` | Multiple valid keys | First byte is `0x02` or `0x03` |
| `test_pubkey_length_33_bytes` | Any valid key | Exactly 33 bytes |

## 6.5 — Bech32 address generation

Module: `address`

| Test | Input | Expected address |
|---|---|---|
| `test_address_from_generator_point` | Compressed pubkey for scalar = 1: `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` | `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` |
| `test_address_from_scalar_two` | Compressed pubkey for scalar = 2: `02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5` | `bc1qq6hag67dl53wl99vzg42z8eyzfz2xlkvxechjp` |
| `test_address_starts_with_bc1q` | Any valid compressed pubkey | Starts with `bc1q` |
| `test_address_length_42` | Any valid compressed pubkey | Exactly 42 characters (P2WPKH) |
| `test_address_is_lowercase` | Any valid compressed pubkey | Entire string is lowercase |
| `test_address_valid_bech32_charset` | Any output | After the `1` separator, contains only valid Bech32 characters (`qpzry9x8gf2tvdw0s3jn54khce6mua7l`) |

## 6.6 — End-to-end deterministic pipeline

Module: `lib.rs` (pipeline_tests)

| Test | Description |
|---|---|
| `test_full_pipeline_deterministic` | Fixed entropy (scalar = 1) through full pipeline: key bytes, WIF (`KwDiBf89...noWn`), pubkey (`0279be66...1798`), address (`bc1qw508d6...f3t4`) all match expected |
| `test_full_pipeline_known_vector_two` | Fixed entropy (scalar = 2) through full pipeline: WIF (`KwDiBf89...tX4`), pubkey (`02c6047f...9ee5`), address (`bc1qq6hag...chjp`) all match expected |
| `test_pipeline_different_entropy_different_outputs` | Two different entropy inputs produce different keys, pubkeys, addresses, and WIFs |

## 6.7 — Output contract

Module: `main.rs` (tests)

| Test | Description |
|---|---|
| `test_plain_output_contains_address` | Default (plain) format: output contains a `bc1q` address |
| `test_plain_output_contains_wif` | Default format: output contains a WIF string |
| `test_plain_output_both_address_and_wif` | Default output contains both address and WIF in same run |
| `test_hex_included_when_present` | When `private_key_hex` is `Some`, output includes the 64-char hex string |
| `test_pubkey_included_when_present` | When `pubkey_hex` is `Some`, output includes the 66-char hex string |
| `test_json_output_is_valid_json` | JSON format: output parses as valid JSON object |
| `test_json_contains_address_and_wif_fields` | JSON has `address` and `wif` fields |
| `test_json_all_fields_when_present` | JSON has all four fields when all options provided |
| `test_json_omits_optional_fields_when_absent` | JSON omits `private_key_hex` and `pubkey_hex` when not requested |
| `test_warnings_contain_key_safety_messages` | Warnings mention that secrets are not stored and re-running generates a new keypair |
| `test_plain_output_does_not_contain_warnings` | `format_output` (stdout path) contains no warning text |

## 6.8 — Statelessness and uniqueness

| Test | Description |
|---|---|
| `test_two_cli_runs_produce_different_keys` | Two invocations of the binary with `--json` produce different addresses and WIFs |
| `test_no_file_artifacts` | After running generate in a temp directory, no new files are created |
| `test_no_env_mutation` | Environment variables before and after running the binary are identical |

## 6.9 — Structural safety checks

| Test | Description |
|---|---|
| `test_no_network_deps` | Structural: `cargo tree` contains none of `reqwest`, `hyper`, `tokio`, `async-std`, `surf`, `ureq`, `curl` |

## 6.10 — CLI integration tests

These invoke the compiled binary and inspect stdout, stderr, and exit code.

| Test | Description |
|---|---|
| `test_cli_generate_exit_code_zero` | `btc-keygen generate` exits with code 0 |
| `test_cli_generate_stdout_has_address_and_wif` | stdout contains both a `bc1q` address and a WIF |
| `test_cli_generate_stderr_has_warnings` | stderr is non-empty (contains safety messaging) |
| `test_cli_json_flag` | `btc-keygen generate --json` outputs valid JSON with `address` and `wif` |
| `test_cli_hex_flag` | `btc-keygen generate --hex` includes 64+ hex digit string in output |
| `test_cli_pubkey_flag` | `btc-keygen generate --pubkey` includes compressed pubkey hex in output |
| `test_cli_all_flags_json` | `btc-keygen generate --hex --pubkey --json` outputs JSON with all four fields |
| `test_cli_no_subcommand_shows_help` | Running with no arguments exits non-zero and shows usage |
| `test_cli_unknown_flag_errors` | `--unknown-flag` produces an error and nonzero exit |

## 6.11 — Doc-tests

| Test | Description |
|---|---|
| `lib.rs` doc example | Crate-level usage example compiles |
| `generate()` doc example | Function-level example compiles |

## Summary

| Category | Count | Location |
|---|---|---|
| Entropy source self-tests | 4 | `entropy.rs` |
| Key boundary validation | 7 | `keygen.rs` |
| Injectable entropy | 6 | `keygen.rs` |
| WIF encoding | 6 | `wif.rs` |
| Public key derivation | 4 | `pubkey.rs` |
| Bech32 address | 6 | `address.rs` |
| End-to-end pipeline | 3 | `lib.rs` |
| Output contract | 11 | `main.rs` |
| Statelessness | 3 | `tests/integration.rs` |
| Structural safety | 1 | `tests/integration.rs` |
| CLI integration | 9 | `tests/integration.rs` |
| Doc-tests | 2 | `lib.rs`, `keygen.rs` |
| **Total** | **62** | |
