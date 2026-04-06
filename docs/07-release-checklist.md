# Release checklist

Step-by-step routine for publishing a new version of btc-keygen.

## 1. Decide the version number

Follow [Semantic Versioning](https://semver.org/):

| Change type | Bump | Example |
|---|---|---|
| Breaking API/CLI change | MAJOR | 0.1.0 → 1.0.0 |
| New feature, no breakage | MINOR | 0.0.2 → 0.1.0 |
| Bug fix, docs, CI | PATCH | 0.0.2 → 0.0.3 |

While the project is `0.x.y`, minor bumps may include breaking changes. Once you tag `1.0.0`, the contract is strict.

## 2. Update version in source files

The version appears in exactly four files:

| File | Location | Format |
|---|---|---|
| `Cargo.toml` | line 3 | `version = "X.Y.Z"` |
| `README.md` | line 5 | `**ALPHA vX.Y.Z**` |
| `site/index.html` | header warning | `ALPHA vX.Y.Z` |
| `site/index.html` | footer warning | `ALPHA vX.Y.Z` |

After editing, run `cargo check` to make sure `Cargo.toml` parses correctly.

## 3. Update the changelog

Edit `CHANGELOG.md` following the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

### Format

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features.

### Changed
- Changes to existing functionality.

### Fixed
- Bug fixes.

### Removed
- Removed features.
```

### Rules

- Use the **exact date** the release is tagged, in `YYYY-MM-DD` format.
- Only include sections (`Added`, `Changed`, `Fixed`, `Removed`) that apply.
- Each entry should be a single clear sentence.
- Write from the user's perspective ("Add JSON output" not "Refactored output module").
- Add a comparison link at the bottom of the file:

```markdown
[X.Y.Z]: https://github.com/aguimaraes/btc-keygen/compare/vPREVIOUS...vX.Y.Z
```

## 4. Run local checks

Run the full CI suite locally before pushing:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

Fix anything that fails. Do not skip these.

## 5. Check crate packaging

```bash
cargo publish --dry-run --allow-dirty
```

This catches issues like missing fields in `Cargo.toml`, files that shouldn't be packaged, or build failures in the packaged crate. Review the file count and size — if it's unexpectedly large, you may need to update the `exclude` list in `Cargo.toml`.

We need --allow-dirty because our changes are not committed yet.

## 6. Commit the version bump

```bash
git add Cargo.toml Cargo.lock README.md site/index.html CHANGELOG.md
git commit -m "Bump version to X.Y.Z"
```

Use a dedicated commit for the version bump. Do not mix it with other changes.

## 7. Tag the release

```bash
git tag -s vX.Y.Z -m "vX.Y.Z"
```

- Always use an annotated, signed tag (`-s`).
- The tag name must match the pattern `v*` (e.g., `v0.0.3`) to trigger the release workflow.

## 8. Push

```bash
git push origin main
git push origin vX.Y.Z
```

Push the commit first, then the tag. Pushing the tag triggers the GitHub Actions release workflow.

## 9. Monitor the release workflow

The release workflow runs three jobs in sequence:

1. **test** — runs `cargo test` on Linux, macOS, and Windows.
2. **build** — compiles binaries for five targets:
   - `x86_64-unknown-linux-musl`
   - `aarch64-unknown-linux-musl`
   - `x86_64-apple-darwin`
   - `aarch64-apple-darwin`
   - `x86_64-pc-windows-gnu`
3. **release** — generates `SHA256SUMS.txt`, creates a GitHub Release with all binaries attached.

Watch the workflow at `https://github.com/aguimaraes/btc-keygen/actions`. If any job fails, fix the issue, delete the tag, re-tag, and push again:

```bash
git tag -d vX.Y.Z
git push origin :refs/tags/vX.Y.Z
# fix, commit, then re-tag and push
```

## 10. Verify the GitHub Release

Once the workflow completes:

- Check the release page at `https://github.com/aguimaraes/btc-keygen/releases/tag/vX.Y.Z`.
- Confirm all five binaries and `SHA256SUMS.txt` are attached.
- Download at least one binary and verify the checksum matches.
- Run the binary to confirm it works: `./btc-keygen generate`.

## 11. Publish to crates.io

```bash
cargo publish
```

This uploads the crate to [crates.io](https://crates.io/crates/btc-keygen). You need to be logged in (`cargo login` with an API token from <https://crates.io/settings/tokens>).

**This is irreversible.** A version published to crates.io cannot be overwritten or deleted (only yanked). Double-check everything before running this command.

### First-time setup

1. Create an account on [crates.io](https://crates.io) (sign in with GitHub).
2. Generate an API token at <https://crates.io/settings/tokens>.
3. Run `cargo login <token>`.

## 12. Post-release

- Verify the crate page at `https://crates.io/crates/btc-keygen`.
- Confirm the documentation rendered correctly at `https://docs.rs/btc-keygen`.
- If the website still shows the old version, check that the GitHub Pages deployment ran (push to `main` triggers it).

## Quick reference

```
cargo fmt --check && cargo clippy -- -D warnings && cargo test
cargo publish --dry-run
git add Cargo.toml Cargo.lock README.md site/index.html CHANGELOG.md
git commit -m "Bump version to X.Y.Z"
git tag -s vX.Y.Z -m "vX.Y.Z"
git push origin main
git push origin vX.Y.Z
# wait for CI to pass
cargo publish
```
