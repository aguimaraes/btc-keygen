# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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

[0.0.2]: https://github.com/aguimaraes/btc-keygen/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/aguimaraes/btc-keygen/releases/tag/v0.0.1
