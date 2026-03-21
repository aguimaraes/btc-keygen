# Module Layout

## Directory structure

```
btc-keygen/
├── Cargo.toml
├── docs/
│   ├── 01-threat-model.md
│   ├── 02-non-goals.md
│   ├── 03-security-assumptions.md
│   ├── 04-dependencies.md
│   ├── 05-module-layout.md
│   ├── 06-test-plan.md
│   └── 07-release-checklist.md
├── src/
│   ├── main.rs          Entry point: CLI parsing, orchestration, output formatting
│   ├── lib.rs           Public API re-exports, crate-level docs, Error type
│   ├── entropy.rs       Entropy source trait + OS CSPRNG implementation
│   ├── keygen.rs        Private key generation, validation, zeroizing wrapper
│   ├── wif.rs           WIF encoding (Base58Check, mainnet, compressed)
│   ├── pubkey.rs        Compressed public key derivation
│   └── address.rs       Native SegWit (P2WPKH) Bech32 address derivation
└── tests/
    └── integration.rs   CLI integration tests (invoke binary, check stdout/stderr)
```

## Public API

The library exposes four functions and two types at the crate root via
`pub use` re-exports. All internal modules are `pub(crate)`.

| Item | Type | Description |
|---|---|---|
| `generate()` | Function | Generate a private key from OS randomness |
| `encode_wif(&key)` | Function | Encode a private key as WIF |
| `derive_pubkey(&key)` | Function | Derive compressed public key |
| `derive_address(&pubkey)` | Function | Derive Bech32 address |
| `PrivateKey` | Struct | Validated, zeroize-on-drop key wrapper |
| `Error` | Struct | Error type for generation failures |

## Module responsibilities

### `lib.rs`

Defines the public API surface. All internal modules are declared
`pub(crate)` and key items are re-exported with `pub use`. Contains the
`Error` type and `From<EntropyError>` conversion. Hosts end-to-end pipeline
tests.

### `entropy.rs`

Defines an `EntropySource` trait with a single method:

```rust
fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), EntropyError>;
```

Provides three implementations:
- `OsEntropy` — production implementation, delegates to `getrandom::getrandom()`
- `FixedEntropy` — test-only (`#[cfg(test)]`), returns deterministic bytes
- `FailingEntropy` — test-only (`#[cfg(test)]`), always returns an error

**Invariant:** `OsEntropy` is the only production entropy source.

**Failure mode:** If `getrandom` fails, the tool aborts immediately. It never
falls back to weaker entropy.

### `keygen.rs`

Contains the `PrivateKey` struct and two generation functions:

- `generate()` (public) — hardcodes `OsEntropy`, returns `Result<PrivateKey, Error>`
- `generate_with_entropy()` (`pub(crate)`) — accepts any `EntropySource` for testing

Fills 32 bytes, validates they represent a scalar in `[1, n-1]` where `n` is
the secp256k1 curve order. Wraps the result in `PrivateKey` which implements
`Zeroize` and `ZeroizeOnDrop`.

Retries with fresh entropy if random bytes fall outside the valid range. A hard
cap of 32 retries acts as a safety net (probability of needing even one retry
is approximately 10^-38).

**Invariant:** Every returned `PrivateKey` is valid for secp256k1.

### `wif.rs`

Pure function that takes a `&PrivateKey` and produces a WIF string:
1. Prepend `0x80` (mainnet)
2. Append `0x01` (compressed key flag)
3. Compute 4-byte checksum (first 4 bytes of double SHA-256)
4. Encode as Base58

Implements Base58 encoding inline (approximately 30 lines) to avoid a
dependency.

**Invariant:** Output starts with `K` or `L` (compressed mainnet WIF) and is 52
characters.

### `pubkey.rs`

Takes a `&PrivateKey`, derives the `secp256k1::PublicKey`, and serializes it
as 33-byte compressed form.

**Invariant:** Output is always 33 bytes, first byte is `0x02` or `0x03`.

### `address.rs`

Takes 33 compressed public key bytes and produces a Bech32 address:
1. Compute Hash160: `RIPEMD160(SHA256(pubkey))` — yields 20 bytes
2. Encode as Bech32 with human-readable part `bc` and witness version 0

**Invariant:** Output starts with `bc1q` and is a valid Bech32 string.

### `main.rs`

Contains all CLI and output formatting logic:

- CLI parsing via `clap` (`generate` subcommand with `--hex`, `--pubkey`, `--json`)
- `KeypairOutput` struct and `Format` enum (private to the binary)
- Plain text and JSON output formatting
- Safety warnings printed to stderr

Orchestrates the full pipeline:
1. Parse CLI arguments
2. Print safety warnings to stderr
3. Generate keypair via `btc_keygen::generate()`
4. Derive WIF, public key, and address via the public API
5. Format and print output
6. Drop all secret material (zeroized automatically)
7. Exit

**Invariant:** No secret material persists after the output function returns.
stdout contains only machine-readable data. All warnings go to stderr.

## Data flow

```
OsEntropy
    |
    v
generate()  -->  PrivateKey (32 bytes, zeroized on drop)
                      |
                      +---> encode_wif(&key)            --> WIF string
                      |
                      +---> derive_pubkey(&key)          --> [u8; 33]
                      |         |
                      |         +---> derive_address(&pubkey) --> "bc1q..."
                      |
                      +---> (optional) hex encoding       --> hex string

main.rs formats output  --> stdout
stderr  <--  safety warnings
```

## Module dependency graph

```
main.rs  (uses public API: generate, encode_wif, derive_pubkey, derive_address)
    |
lib.rs   (re-exports from internal modules)
    ├── entropy.rs       (no internal deps)
    ├── keygen.rs        (depends on: entropy)
    ├── wif.rs           (depends on: keygen for PrivateKey type)
    ├── pubkey.rs         (depends on: keygen for PrivateKey type)
    └── address.rs       (no internal deps)
```

All encoding/derivation modules are pure functions. `keygen` is the only
module with internal state (retry loop). This makes each module independently
testable.
