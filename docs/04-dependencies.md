# Dependency Proposal

## Principle

Every dependency is an attack surface. Each crate must be justified by one of:

1. It replaces cryptography we must not implement ourselves
2. It provides a security property we cannot easily achieve in safe Rust
3. It prevents bugs in non-trivial encoding logic

## Approved dependencies

### `secp256k1`

- **Fuzzing stubs are rejected at compile time:** `RUSTFLAGS --cfg
  secp256k1_fuzz` replaces libsecp256k1 with stubs whose
  `secp256k1_ec_pubkey_create` copies the secret key into the public key, so
  every address such a build derives would carry its own private key. A
  `compile_error!` in `src/pubkey.rs` refuses it.

- **Purpose:** Elliptic curve key generation and public key derivation
- **Justification:** Rust binding to Bitcoin Core's `libsecp256k1`, the most
  reviewed secp256k1 implementation in the ecosystem. We must not implement EC
  math ourselves.
- **Note:** The crate vendors the C `libsecp256k1` source and compiles it. This
  is intentional: it uses the audited C implementation rather than a Rust
  reimplementation.

### `bitcoin_hashes`

- **Purpose:** SHA-256, RIPEMD-160, and Hash160 (RIPEMD160(SHA256(x)))
- **Justification:** From the `rust-bitcoin` project. Needed for WIF checksum
  (double SHA-256) and address derivation (Hash160 of public key). Avoids pulling
  in a general-purpose crypto library.

### `bech32`

- **Purpose:** Bech32 encoding for native SegWit (P2WPKH) addresses
- **Justification:** Reference implementation of BIP173 and BIP350. Bech32 has
  a specific checksum algorithm (BCH code) that must not be hand-rolled. Small,
  focused crate.

### `zeroize`

- **Purpose:** Secure memory zeroing on drop
- **Justification:** Ensures private key bytes are overwritten when the holding
  struct is dropped. Uses compiler barriers to prevent dead-store elimination.
  Tiny crate, widely audited.
- **Floor `1.5.3`:** the `derive` feature did not exist before 1.5.0, and 1.5.0
  to 1.5.2 are yanked, so the earlier `"1"` requirement named ten versions that
  could not resolve. Manifest honesty rather than a security fix.

### `getrandom`

- **Purpose:** Direct access to OS-provided CSPRNG
- **Justification:** Used by the `OsEntropy` implementation to fill private key
  bytes from the OS entropy source (`getrandom(2)` on Linux and FreeBSD, with a
  `/dev/urandom` fallback where that syscall is unavailable, `getentropy` on
  macOS, `ProcessPrng` on Windows). The sole entropy source used by
  the tool; `entropy.rs` calls it directly.
- **Floor `0.4.2`, do not lower it:** in 0.4.0 and 0.4.1 the Windows backend
  checked `ProcessPrng`'s return value with a `debug_assert!` that the release
  profile compiles out, so `getrandom::fill` could return `Ok(())` having
  written no bytes. Fixed in 0.4.2, whose own comment names Wine through 11.2
  as a real trigger. Since this is the only production entropy call in the
  crate, a fail-open version of it is the worst dependency defect available to
  us.
- **Backend override is rejected at compile time:** `RUSTFLAGS --cfg
  getrandom_backend="..."` silently replaces the entropy source. All nine
  values getrandom 0.4 defines are refused by a `compile_error!` in
  `src/entropy.rs`. The `check-cfg` list in `Cargo.toml` must be re-checked
  whenever the getrandom minor version moves, because a backend added in a
  future 0.4.x would be neither listed there nor blocked.

### `clap`

- **Purpose:** CLI argument parsing
- **Justification:** Provides the `generate` subcommand and optional flags
  (`--from-hex`, `--hex`, `--pubkey`, `--json`). While hand-rolling argument parsing is
  possible, `clap` prevents bugs in flag handling and provides standard help
  output. Use the `derive` feature for minimal boilerplate.
- **Default features dropped:** `color` and `suggestions` pulled an ANSI escape
  parser and terminal detection into an offline key generator. Removing them
  drops 11 crates from `Cargo.lock` and 16,544 bytes from the release binary,
  at the cost of coloured help and did-you-mean hints. `help` is load-bearing;
  removing it fails a test. `usage` and `error-context` cost no extra crates.

## Dev-only dependencies

None.

## Rejected alternatives

| Crate                  | Reason for rejection                                                                                                                                                           |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `bitcoin` (full)       | Too large. Includes transaction parsing, script handling, networking types. We need only hashing and encoding primitives.                                                      |
| `ring` / `openssl`     | Unnecessary. `secp256k1` + `bitcoin_hashes` covers all needed crypto without pulling in TLS or general-purpose crypto.                                                         |
| `rand`                 | Not needed. Key bytes come straight from `getrandom` and are validated with `secp256k1::SecretKey::from_byte_array()`. The `secp256k1` `rand` feature is disabled.             |
| `serde` / `serde_json` | The JSON structure is trivially small (3-4 fields). Hand-writing JSON avoids a large transitive dependency tree.                                                               |
| `base58` / `bs58`      | Base58 encoding is roughly 30 lines. Implementing it inline avoids a dependency for trivial logic. Tested against known vectors.                                               |

## Dependency audit process

Before any release:

1. Run `cargo audit` to check for known vulnerabilities
2. Run `cargo tree` to review the full transitive dependency graph
3. Confirm `Cargo.lock` is committed and up to date; CI and release builds run
   with `--locked`
4. Verify no crate in the tree uses `std::net`, `reqwest`, `hyper`, or any
   networking primitives
