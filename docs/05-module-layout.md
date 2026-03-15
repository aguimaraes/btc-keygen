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
│   └── 06-test-plan.md
├── src/
│   ├── main.rs          Entry point: CLI parsing, orchestration, stderr warnings
│   ├── lib.rs           Re-exports for testability; no business logic
│   ├── entropy.rs       Entropy source trait + OS CSPRNG implementation
│   ├── keygen.rs        Private key generation, validation, zeroizing wrapper
│   ├── wif.rs           WIF encoding (Base58Check, mainnet, compressed)
│   ├── pubkey.rs        Compressed public key derivation
│   ├── address.rs       Native SegWit (P2WPKH) Bech32 address derivation
│   └── output.rs        Output formatting (plain text and JSON)
└── tests/
    └── integration.rs   CLI integration tests (invoke binary, check stdout/stderr)
```

## Module responsibilities

### `entropy.rs`

Defines an `EntropySource` trait with a single method:

```rust
fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), EntropyError>;
```

Provides two implementations:
- `OsEntropy` — production implementation, delegates to `getrandom::getrandom()`
- `FixedEntropy` — test-only (`#[cfg(test)]`), returns deterministic bytes

**Invariant:** `OsEntropy` is the only production entropy source.

**Failure mode:** If `getrandom` fails, the tool aborts immediately. It never
falls back to weaker entropy.

### `keygen.rs`

Takes an `EntropySource`, fills 32 bytes, validates they represent a scalar in
`[1, n-1]` where `n` is the secp256k1 curve order.

Wraps the result in a `PrivateKey` struct that implements `Zeroize` and
`ZeroizeOnDrop`.

Retries with fresh entropy if random bytes fall outside the valid range. A hard
cap of 256 retries acts as a safety net (probability of needing even one retry
is approximately 10^-38).

**Invariant:** Every returned `PrivateKey` is valid for secp256k1.

### `wif.rs`

Pure function that takes 32 private key bytes and produces a WIF string:
1. Prepend `0x80` (mainnet)
2. Append `0x01` (compressed key flag)
3. Compute 4-byte checksum (first 4 bytes of double SHA-256)
4. Encode as Base58

Implements Base58 encoding inline (approximately 30 lines) to avoid a
dependency.

**Invariant:** Output starts with `K` or `L` (compressed mainnet WIF) and is 52
characters.

### `pubkey.rs`

Takes a `secp256k1::SecretKey`, derives the `secp256k1::PublicKey`, and
serializes it as 33-byte compressed form.

**Invariant:** Output is always 33 bytes, first byte is `0x02` or `0x03`.

### `address.rs`

Takes 33 compressed public key bytes and produces a Bech32 address:
1. Compute Hash160: `RIPEMD160(SHA256(pubkey))` — yields 20 bytes
2. Encode as Bech32 with human-readable part `bc` and witness version 0

**Invariant:** Output starts with `bc1q` and is a valid Bech32 string.

### `output.rs`

Takes the generated keypair data and CLI flags, formats output.

Three public functions:
- `print_output(keypair, format)` — writes to stdout (used by `main.rs`)
- `format_output(writer, keypair, format)` — writes to any `dyn Write` (used
  by tests to capture output into a buffer without touching stdout)
- `print_warnings(writer)` — writes safety warnings to any `dyn Write`

Two formats:
- **Plain text** (default) — labeled key-value pairs, one per line
- **JSON** — hand-written JSON with expected keys

**Invariant:** stdout contains only machine-readable data. All warnings and
human-readable messages go to stderr.

### `main.rs`

Orchestrates the full pipeline:
1. Parse CLI arguments via `clap`
2. Print safety warnings to stderr
3. Generate keypair via `keygen::generate()` with `OsEntropy`
4. Derive WIF, public key, and address
5. Format and print output
6. Drop all secret material (zeroized automatically)
7. Exit

**Invariant:** No secret material persists after the output function returns.

### `lib.rs`

Re-exports public module interfaces for integration testing. Contains no logic.

## Data flow

```
OsEntropy
    |
    v
keygen::generate()  -->  PrivateKey (32 bytes, zeroized on drop)
                              |
                              +---> wif::encode_wif(&bytes)        --> WIF string
                              |
                              +---> pubkey::derive_pubkey(&secret)  --> [u8; 33]
                              |         |
                              |         +---> address::derive_address(&pubkey) --> "bc1q..."
                              |
                              +---> (optional) hex encoding         --> hex string

output::format(address, wif, hex?, pubkey?, json?)  --> stdout
stderr  <--  safety warnings
```

## Module dependency graph

```
main.rs
  ├── entropy.rs       (no internal deps)
  ├── keygen.rs        (depends on: entropy)
  ├── wif.rs           (no internal deps)
  ├── pubkey.rs        (no internal deps)
  ├── address.rs       (no internal deps)
  └── output.rs        (no internal deps)
```

All modules except `keygen` are pure functions with no internal dependencies.
This makes them independently testable.
