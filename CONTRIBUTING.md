# Contributing

## Philosophy

This tool does one job: generate a Bitcoin keypair offline. Every decision
follows from that:

- **Small and auditable.** A competent developer should be able to read and
  verify the entire codebase in an afternoon. Don't add code that makes that
  harder.
- **Fully tested.** Every component has tests, including known-answer vectors
  from the Bitcoin ecosystem. New code needs tests.
- **As safe as we can make it.** Secrets are zeroized, entropy comes from the
  OS CSPRNG, crypto is delegated to audited libraries, and there is zero
  networking code. Don't weaken any of these guarantees.
- **Minimal dependencies.** Every dependency is an attack surface. Each one
  must be justified. If something can be done in 30 lines, don't add a crate.
  See `docs/04-dependencies.md` for the rationale behind each dependency.
- **The tool generates, the operator secures.** The tool prints a keypair and
  exits. It does not save, encrypt, or transmit secrets. Protecting the output
  is the operator's responsibility. See `docs/01-threat-model.md`.
- **No scope creep.** This is not a wallet, not an HD key derivator, not a
  transaction signer. See `docs/02-non-goals.md` for the full list of things
  we intentionally don't do.

If a proposed change makes the tool harder to audit, less safe, or broader in
scope, it probably doesn't belong here.

## Getting started

```bash
git clone https://github.com/aguimaraes/btc-keygen.git
cd btc-keygen
cargo test
```

Requires [Rust](https://www.rust-lang.org/tools/install) (stable) and a C
compiler (for libsecp256k1).

## Branch naming

Use the format `feature/<short-description>`:

```
feature/refactor-public-api
feature/add-testnet-support
feature/fix-wif-checksum
```

Use `feature/` for all branches — features, fixes, refactors. Keep the
description short and lowercase with hyphens.

## Making changes

1. Create a branch from `main`
2. Make your changes
3. Run the full check suite before pushing:
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   ```
4. Commit with a clear, concise message
5. Open a pull request against `main`

## Code style

- Format with `cargo fmt` (edition 2024 rules via `rustfmt.toml`)
- No clippy warnings (`cargo clippy -- -D warnings`)
- Keep the public API minimal — internal modules are `pub(crate)`
- No new dependencies without justification (see `docs/04-dependencies.md`)

## Tests

- Every new function needs tests
- Use known-answer vectors from Bitcoin wiki where applicable
- Use `FixedEntropy` / `PrivateKey::from_bytes()` for deterministic tests
- Run `cargo test` — all 62 tests must pass

## Commits

- Use clear, imperative commit messages ("Add X" not "Added X")
- Sign your commits (`git commit -s`)
- Keep commits focused — one logical change per commit

## Security

This is a cryptographic tool. If you find a security issue, please report it
privately to the maintainer rather than opening a public issue.
