# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0] - 2026-08-03

### Added

- `--from-hex -` reads the private key from stdin, keeping it out of the process
  argument list and the shell history; it prompts when run interactively
- Import from stdin tolerates a missing trailing newline, CRLF, surrounding
  whitespace, and uppercase hex, and rejects empty or over-long input rather
  than silently deriving a different key
- `SecretWif` and `SecretKeyHex` (aliases of `SecretAscii<N>`): fixed-size
  buffers that zeroize on drop, redact their `Debug` output, and cannot be
  cloned, copied, or printed with `{}`
- `PrivateKey::to_hex()` returns the raw private key as a `SecretKeyHex`
- A memory-residue test suite (`tests/no_secret_residue.rs`) that records the
  contents of every freed heap block and asserts none still holds key material,
  with a per-operation allocation and byte budget

### Changed

- **Breaking:** `encode_wif` returns `SecretWif` instead of `String`, so library
  callers get erase-on-drop behavior instead of having to add it themselves
- **Breaking:** `is_valid_key` takes `&[u8; 32]` instead of `[u8; 32]`, so
  testing a candidate key no longer copies it
- The WIF and the private-key hex are written directly into their result buffer,
  which takes encoding a WIF from 134 heap allocations to one, and the private
  key hex from 35 to one. None of those short-lived buffers were erased before
  being freed, so each one left a copy of key material on the heap
- `PrivateKey` keeps its bytes in a heap buffer, so moving one copies a pointer
  instead of memcpying the key into a fresh stack slot that nothing erases
- Every constructor fills that buffer in place: OS entropy is written straight
  into it, and `from_hex` decodes into it, so an assembled key is never staged
  in a bare stack array
- The documentation now states what erasure does not cover: memory the OS moved
  to swap or a crash dump, the stack libsecp256k1 uses while deriving a public
  key, copies the optimizer keeps alive, and anything obtained through
  `as_bytes()`, `to_secret_key()`, or an `expose_*` method
- CLI output is unchanged, byte for byte, across every flag combination

### Deprecated

- Passing the private key as an argument value (`--from-hex <HEX>`), which the
  shell writes to its history file and which is visible to `ps` for the lifetime
  of the command. Use `--from-hex -` instead. Removal is scheduled for 0.4.0

### Fixed

- `PrivateKey::from_hex` no longer leaves an unerased copy of the decoded key in
  a stack buffer
- `derive_pubkey` erases the `secp256k1::SecretKey` copy it creates, and
  `PrivateKey::to_secret_key` now documents that the type it returns is `Copy`,
  does not erase itself, and falls outside the crate's guarantees

## [0.2.0] - 2026-08-02

### Added

- Release binaries are now smoke-tested on every target OS (Linux x86_64 and
  aarch64, macOS x86_64 and aarch64, Windows, FreeBSD) before a release is
  published
- Markdown linting in CI

### Changed

- All secret buffers owned by the process (the WIF string, the optional
  private key hex, and the WIF encoding buffers) are now zeroized after use;
  previously only the raw private key bytes were
- Failures now exit via `ExitCode` instead of `process::exit`, so destructors
  and zeroization also run on error paths
- Dropped the unused secp256k1 `rand` feature, removing six crates from the
  compiled dependency tree
- Updated `bitcoin_hashes` to 1.1 and `bech32` to 0.12; raised the minimum
  supported Rust version to 1.97
- The release workflow grants write permissions only to the publish job
- Documentation aligned with actual behavior (zeroization scope, `--from-hex`
  in the non-goals, dependency pinning via `Cargo.lock`)

## [0.1.0] - 2026-07-18

### Changed

- **License changed from `MIT OR Apache-2.0` to `GPL-3.0-or-later`.** Releases
  0.0.1–0.0.5 remain available under their original permissive terms; 0.1.0
  onward is copyleft. Downstream code that links or bundles this crate must now
  comply with the GPL.

## [0.0.5] - 2026-04-24

### Added

- `--from-hex` CLI flag to accept a user-provided 64-character hex private key instead of OS-generated entropy
- `PrivateKey::from_bytes()` and `PrivateKey::from_hex()` as public library constructors with scalar validation

### Changed

- Release builds now pass `--locked` to Cargo, pinning shipped binaries to the exact transitive dependency versions recorded in `Cargo.lock`

## [0.0.4] - 2026-04-06

### Added

- Added documentation for using this as a crate

### Changed

- Update `secp256k1`, `getrandom` and `bitcoin_hashes` dependencies.

### Removed

- Removed `serde_json` as a dev-dependency to reduce auditing surface further.

### Fixed

- Fixed download instructions on the website

## [0.0.3] - 2026-03-21

### Added

- Public library API: `generate()`, `encode_wif()`, `derive_pubkey()`, `derive_address()`
- Crate-level documentation with usage example and API reference table
- Doc comments on all public functions and types
- `rustfmt.toml` for consistent formatting with edition 2024
- "For developers" section on the website with library usage guide
- Release checklist in `docs/07-release-checklist.md`
- `CHANGELOG.md`
- `rust-version` (MSRV 1.94) and `exclude` fields in `Cargo.toml`
- 2 doc-tests for compile-time documentation verification

### Changed

- Upgrade to Rust edition 2024
- Refactor all internal modules to `pub(crate)` visibility
- `encode_wif()` now accepts `&PrivateKey` instead of `&[u8; 32]`
- `derive_pubkey()` now accepts `&PrivateKey` instead of `&SecretKey`
- Move output formatting logic from library into binary
- Split `generate()` into public API (hardcoded OS entropy) and internal `generate_with_entropy()` (for testing)
- Gate `FixedEntropy`, `FailingEntropy`, and `PrivateKey::from_bytes()` behind `#[cfg(test)]`
- Update module layout and test plan documentation to reflect new architecture
- Test count increased from 60 to 62

### Removed

- `output.rs` as a library module (moved to `main.rs`)

## [0.0.2] - 2026-03-18

### Added

- CI pipeline with rustfmt check, clippy linting, and test suite on push
- `rust-toolchain.toml` pinning the stable channel with rustfmt and clippy components
- `.editorconfig` for consistent formatting across editors
- Dependabot configuration for Rust toolchain updates

### Fixed

- Formatting and clippy warnings across the entire codebase

## [0.0.1] - 2026-03-15

### Added

- Offline Bitcoin key generation using OS CSPRNG (`getrandom`)
- secp256k1 private key validation (scalar in [1, n-1] with retry)
- WIF encoding (Base58Check, compressed, mainnet)
- Compressed public key derivation via libsecp256k1
- Native SegWit (Bech32/P2WPKH) address derivation
- Memory zeroization of private key material on drop
- CLI with `generate` subcommand and `--hex`, `--pubkey`, `--json` flags
- Plain text and JSON output formats
- Safety warnings printed to stderr on every run
- 60 automated tests including known-answer vectors from Bitcoin wiki
- Cross-platform release builds (Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64)
- SHA256 checksum generation for release artifacts
- GitHub Pages website with usage guide, security design, and FAQ
- SEO metadata (Open Graph, Twitter cards, sitemap, robots.txt)
- GitHub Sponsors and Bitcoin donation address
- Threat model, security assumptions, and dependency documentation

[0.3.0]: https://github.com/aguimaraes/btc-keygen/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/aguimaraes/btc-keygen/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/aguimaraes/btc-keygen/compare/v0.0.5...v0.1.0
[0.0.5]: https://github.com/aguimaraes/btc-keygen/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/aguimaraes/btc-keygen/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/aguimaraes/btc-keygen/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/aguimaraes/btc-keygen/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/aguimaraes/btc-keygen/releases/tag/v0.0.1
