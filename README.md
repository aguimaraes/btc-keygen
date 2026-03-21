# btc-keygen

Minimal offline Bitcoin key generator for cold storage.

> **ALPHA v0.0.3** — This software has not been independently audited. Do not use with funds you cannot afford to lose.

## What it does

Generates a Bitcoin private key and its corresponding native SegWit (Bech32) address in a single execution. Prints both to stdout, keeps no state, and exits. Designed to run on an air-gapped machine for cold storage key ceremonies.

```
$ btc-keygen generate
address: bc1q...
wif: K...
```

Every run creates a new keypair. The tool does not store secrets. If you lose the output, there is no way to recover the key.

## Features

- Cryptographically secure randomness from the OS
- secp256k1 validation using Bitcoin Core's libsecp256k1
- Compressed public keys, native SegWit (Bech32) addresses
- WIF private key export
- Optional hex and public key output
- JSON output for scripting
- Memory zeroization of secret material on exit
- Zero network code — fully offline
- 62 automated tests including known-answer vectors
- Cross-platform: Linux, macOS, Windows, BSDs

## Library usage

Add to your project:

```
cargo add btc-keygen
```

```rust
let key = btc_keygen::generate()?;
let wif = btc_keygen::encode_wif(&key);
let pubkey = btc_keygen::derive_pubkey(&key);
let address = btc_keygen::derive_address(&pubkey);
```

| Function | Input | Output |
|---|---|---|
| `generate()` | — | `Result<PrivateKey, Error>` |
| `encode_wif(&key)` | `&PrivateKey` | `String` (starts with `K` or `L`) |
| `derive_pubkey(&key)` | `&PrivateKey` | `[u8; 33]` (compressed public key) |
| `derive_address(&pubkey)` | `&[u8; 33]` | `String` (Bech32 address, `bc1q...`) |

`PrivateKey` zeroizes its bytes when dropped. Full API docs at [docs.rs/btc-keygen](https://docs.rs/btc-keygen).

## Install (CLI)

Download a pre-built binary from the [latest release](https://github.com/aguimaraes/btc-keygen/releases/latest), verify the SHA256 checksum, and run it.

Or build from source:

```
git clone https://github.com/aguimaraes/btc-keygen.git
cd btc-keygen
cargo build --release
./target/release/btc-keygen generate
```

Requires [Rust](https://www.rust-lang.org/tools/install) and a C compiler.

## Usage

```
btc-keygen generate              # address + WIF
btc-keygen generate --hex        # also show raw private key hex
btc-keygen generate --pubkey     # also show compressed public key
btc-keygen generate --json       # JSON output
btc-keygen generate --hex --pubkey --json   # everything
```

## Security

This tool is designed for air-gapped cold storage key generation. See the [website](https://aguimaraes.github.io/btc-keygen) for a plain-language explanation, or the [docs/](docs/) directory for the full threat model, security assumptions, and dependency analysis.

## License

Licensed under either of

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
