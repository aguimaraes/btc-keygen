# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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

[0.0.5]: https://github.com/aguimaraes/btc-keygen/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/aguimaraes/btc-keygen/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/aguimaraes/btc-keygen/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/aguimaraes/btc-keygen/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/aguimaraes/btc-keygen/releases/tag/v0.0.1
