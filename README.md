# btc-keygen

Minimal offline Bitcoin key generator for cold storage.

## What it does

Generates a Bitcoin private key and its corresponding native SegWit (Bech32) address in a single execution. Prints both to stdout, keeps no state, and exits. Designed to run on an air-gapped machine for cold storage key ceremonies.

```console
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
- Secret buffers are zeroized in memory when dropped
- Zero network code, fully offline
- Automated tests including known-answer vectors from the Bitcoin wiki
- Cross-platform: Linux, macOS, Windows, BSDs

## Library usage

Add to your project:

```bash
cargo add btc-keygen
```

```rust
let key = btc_keygen::generate()?;
let wif = btc_keygen::encode_wif(&key);
let pubkey = btc_keygen::derive_pubkey(&key);
let address = btc_keygen::derive_address(&pubkey);

println!("{address}");
println!("{}", wif.expose_str()); // exposure is explicit and copies escape here
```

| Function                        | Input                 | Output                                         |
| ------------------------------- | --------------------- | ---------------------------------------------- |
| `generate()`                    | (none)                | `Result<PrivateKey, Error>`                    |
| `PrivateKey::from_bytes(bytes)` | `[u8; 32]`            | `Result<PrivateKey, Error>` (validated scalar) |
| `PrivateKey::from_hex(hex)`     | `&str` (64 hex chars) | `Result<PrivateKey, Error>` (validated scalar) |
| `key.to_hex()`                  | `&PrivateKey`         | `SecretKeyHex` (64 hex ASCII bytes)            |
| `encode_wif(&key)`              | `&PrivateKey`         | `SecretWif` (52 Base58 ASCII bytes)            |
| `derive_pubkey(&key)`           | `&PrivateKey`         | `[u8; 33]` (compressed public key)             |
| `derive_address(&pubkey)`       | `&[u8; 33]`           | `String` (Bech32 address, `bc1q...`)           |

Secret material never leaves the library as a `String`. `SecretWif` and
`SecretKeyHex` zeroize on drop, redact their `Debug` output, and cannot be
cloned, copied, or printed with `{}`; read them with `expose_bytes()` or
`expose_str()`. `PrivateKey` zeroizes its bytes when dropped.

Erasure covers the buffers the library owns. It does not reach copies you ask
for via `as_bytes()`, `to_secret_key()`, or an `expose_*` method, memory the OS
moved to swap or a crash dump, or the stack libsecp256k1 uses while deriving a
public key. See [what we cannot erase](docs/03-security-assumptions.md) for the
full list. Full API docs at
[docs.rs/btc-keygen](https://docs.rs/btc-keygen).

## Install (CLI)

Download a pre-built binary from the
[latest release](https://github.com/aguimaraes/btc-keygen/releases/latest),
verify the SHA256 checksum, and run it.

Or build from source:

```bash
git clone https://github.com/aguimaraes/btc-keygen.git
cd btc-keygen
cargo build --release
./target/release/btc-keygen generate
```

Requires [Rust](https://www.rust-lang.org/tools/install) and a C compiler.

## Usage

```bash
btc-keygen generate              # address + WIF
btc-keygen generate --hex        # also show raw private key hex
btc-keygen generate --pubkey     # also show compressed public key
btc-keygen generate --json       # JSON output
btc-keygen generate --hex --pubkey --json   # everything

# Import your own 64-character hex private key instead of using OS entropy.
# Read it from stdin so the key never appears in the process arguments:
btc-keygen generate --from-hex - < key.hex   # from a file
btc-keygen generate --from-hex -             # prompts when run interactively

# Accepted, but avoid it: a key passed as an argument is saved to your shell
# history and is visible to `ps` while the command runs. The tool warns when
# you do this, and it cannot undo either exposure.
btc-keygen generate --from-hex <HEX>
```

Note that `echo $HEX | btc-keygen generate --from-hex -` still records the key
in your shell history, because the shell logs the whole pipeline. Read from a
file or type the key at the prompt.

## Security

This tool is designed for air-gapped cold storage key generation. See the
[website](https://aguimaraes.github.io/btc-keygen) for a plain-language
explanation, or the [docs/](docs/) directory for the full threat model,
security assumptions, and dependency analysis.

## License

Licensed under the [GNU General Public License v3.0 or later](LICENSE).

Versions 0.0.1–0.0.5 were released under `MIT OR Apache-2.0`; those releases
remain available under those terms. Version 0.1.0 onward is GPL-3.0-or-later.
