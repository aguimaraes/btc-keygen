# Non-Goals

The following are explicitly out of scope for this tool. They must not be added
without a deliberate design review.

## Wallet functionality

- **HD wallet derivation** — No BIP32, BIP39, or BIP44. This tool generates
  single standalone keys.
- **Mnemonic phrases** — No seed words. Output is WIF plus address.
- **Transaction signing or broadcasting** — This is a key generator, not a
  wallet.
- **Blockchain queries** — No network code of any kind.
- **Address reuse detection** — No state between runs.
- **Wallet syncing** — No persistent wallet file or keystore.

## Key management

- **Key import or recovery** — The tool generates keys; it does not consume
  them.
- **Passphrase protection** — No BIP38 encryption of keys.
- **Deterministic generation from user seeds** — All entropy comes from the OS
  CSPRNG. The tool does not accept user-provided entropy in v1 to avoid the risk
  of weak seeds.
- **Vanity address generation** — No brute-force key search.

## Network and address types

- **Testnet or regtest** — Mainnet only in v1, to keep encoding paths minimal.
- **Legacy address formats** — No P2PKH (1...) or P2SH-P2WPKH (3...). Native
  SegWit (Bech32, bc1q...) only.
- **Multi-signature** — Single key, single address.

## Output and UI

- **QR codes** — Text output only.
- **GUI** — Command-line interface only.
- **Encryption of output** — The tool prints plaintext. The operator is
  responsible for securing the output medium.

## Performance

- **Optimization** — One key per run. Performance is irrelevant. Correctness
  and auditability take absolute priority.
