# Dependency Proposal

## Principle

Every dependency is an attack surface. Each crate must be justified by one of:

1. It replaces cryptography we must not implement ourselves
2. It provides a security property we cannot easily achieve in safe Rust
3. It prevents bugs in non-trivial encoding logic

## Approved dependencies

### `secp256k1`

- **Purpose:** Elliptic curve key generation and public key derivation
- **Justification:** Rust binding to Bitcoin Core's `libsecp256k1`, the most
  reviewed secp256k1 implementation in the ecosystem. We must not implement EC
  math ourselves. Enable the `rand-std` feature for CSPRNG-based key generation.
- **Transitive deps:** `getrandom`, `rand_core`, `cc` (build-time, compiles
  vendored C source)
- **Note:** The crate vendors the C `libsecp256k1` source and compiles it. This
  is intentional — it uses the audited C implementation rather than a Rust
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

### `getrandom`

- **Purpose:** Direct access to OS-provided CSPRNG
- **Justification:** Used by the `OsEntropy` implementation to fill private key
  bytes from the OS entropy source (`getrandom(2)` on Linux, `getentropy` on
  macOS/BSDs, `BCryptGenRandom` on Windows). Already a transitive dependency of
  `secp256k1`, but listed as a direct dependency so `entropy.rs` can call it
  explicitly rather than routing through `secp256k1`'s key generation.

### `clap`

- **Purpose:** CLI argument parsing
- **Justification:** Provides the `generate` subcommand and optional flags
  (`--hex`, `--pubkey`, `--json`). While hand-rolling argument parsing is
  possible, `clap` prevents bugs in flag handling and provides standard help
  output. Use the `derive` feature for minimal boilerplate.

## Dev-only dependencies

### `serde_json` (dev-dependency)

- **Purpose:** JSON parsing in tests only
- **Justification:** Used in integration tests and output contract tests to
  validate that `--json` output is well-formed JSON with the expected fields.
  Not compiled into the release binary.

## Rejected alternatives

| Crate | Reason for rejection |
|---|---|
| `bitcoin` (full) | Too large. Includes transaction parsing, script handling, networking types. We need only hashing and encoding primitives. |
| `ring` / `openssl` | Unnecessary. `secp256k1` + `bitcoin_hashes` covers all needed crypto without pulling in TLS or general-purpose crypto. |
| `rand` | Not needed directly. The `secp256k1` crate with `rand-std` uses `getrandom` internally. For testing with injectable entropy, we use `secp256k1::SecretKey::from_byte_array()`. |
| `serde` / `serde_json` | The JSON structure is trivially small (3-4 fields). Hand-writing JSON avoids a large transitive dependency tree. |
| `base58` / `bs58` | Base58 encoding is roughly 30 lines. Implementing it inline avoids a dependency for trivial logic. Tested against known vectors. |

## Dependency audit process

Before any release:

1. Run `cargo audit` to check for known vulnerabilities
2. Run `cargo tree` to review the full transitive dependency graph
3. Pin exact versions in `Cargo.toml`
4. Verify no crate in the tree uses `std::net`, `reqwest`, `hyper`, or any
   networking primitives
