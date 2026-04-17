# Security Assumptions

These assumptions must hold true for the tool to provide its security
guarantees. If any assumption is violated, the corresponding consequence applies.

| # | Assumption | Consequence if violated |
|---|---|---|
| A1 | The OS CSPRNG (`getrandom` / `/dev/urandom`) provides cryptographically secure random bytes | Generated keys are predictable |
| A2 | The machine is air-gapped and trusted (no network, no malicious processes) | Side channels and memory inspection become viable attack vectors |
| A3 | `libsecp256k1` (via the `secp256k1` crate) correctly implements EC operations and is constant-time | Public key derivation may be incorrect or vulnerable to timing attacks |
| A4 | The Rust compiler and standard library are not backdoored | All security guarantees are void (same for any compiled software) |
| A5 | The operator captures and securely stores the full output of each run | Loss of the WIF means permanent loss of funds sent to the generated address |
| A6 | The operator does not run the tool in an environment that logs stdout | Secrets are not inadvertently persisted by shell history, `script`, or audit systems |
| A7 | SHA-256 and RIPEMD-160 are collision-resistant and preimage-resistant | Address derivation is unsound |
| A8 | Base58Check and Bech32 encoding implementations are correct | Keys and addresses are invalid on the Bitcoin network |
| A9 | When `--from-hex` is used, the caller sourced the 32 bytes from a high-entropy, trusted process | The generated key is as weak as the caller's input; scalar validation does not detect low-entropy bytes |

## Trust boundaries

```
+---------------------------------------------------+
|  Trusted: this tool's process                     |
|  - Private key bytes exist only here              |
|  - Zeroized on drop                               |
+---------------------------------------------------+
        |
        | stdout (WIF, address, optional hex/pubkey)
        v
+---------------------------------------------------+
|  Operator responsibility                          |
|  - Capture output                                 |
|  - Secure storage                                 |
|  - Machine trust (air-gap, no logging, no swap)   |
+---------------------------------------------------+
        |
        | (out of scope)
        v
+---------------------------------------------------+
|  Bitcoin network                                  |
|  - Tool never communicates with this              |
+---------------------------------------------------+
```

## What we trust

- The OS kernel entropy subsystem
- The `libsecp256k1` C library (Bitcoin Core's reference implementation)
- The `bitcoin_hashes` crate (SHA-256, RIPEMD-160)
- The `bech32` crate (BIP173/BIP350 reference implementation)
- The Rust compiler and standard library

## What we do not trust

- Network availability (tool works fully offline)
- Quality of user-provided key bytes when `--from-hex` is used (validated as a valid scalar, but not for entropy)
- Filesystem persistence (nothing written to disk)
- Other processes on the machine (mitigated by air-gap assumption)
- Shell environment (warnings issued about logging)
