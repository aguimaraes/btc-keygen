# Security Assumptions

These assumptions must hold true for the tool to provide its security
guarantees. If any assumption is violated, the corresponding consequence applies.

| # | Assumption | Consequence if violated |
| --- | --- | --- |
| A1 | The OS CSPRNG (`getrandom` / `/dev/urandom`) provides cryptographically secure random bytes | Generated keys are predictable |
| A2 | The machine is air-gapped and trusted (no network, no malicious processes) | Side channels and memory inspection become viable attack vectors |
| A3 | `libsecp256k1` (via the `secp256k1` crate) correctly implements EC operations and is constant-time | Public key derivation may be incorrect or vulnerable to timing attacks |
| A4 | The Rust compiler and standard library are not backdoored | All security guarantees are void (same for any compiled software) |
| A5 | The operator captures and securely stores the full output of each run | Loss of the WIF means permanent loss of funds sent to the generated address |
| A6 | The operator does not run the tool in an environment that logs stdout | The WIF and any requested hex are persisted by `script`, terminal scrollback, or audit systems, where the tool cannot erase them |
| A7 | SHA-256 and RIPEMD-160 are collision-resistant and preimage-resistant | Address derivation is unsound |
| A8 | Base58Check and Bech32 encoding implementations are correct | Keys and addresses are invalid on the Bitcoin network |
| A9 | When `--from-hex` is used, the caller sourced the 32 bytes from a high-entropy, trusted process | The generated key is as weak as the caller's input; scalar validation does not detect low-entropy bytes |
| A10 | An imported key is supplied on stdin (`--from-hex -`), not as a command-line argument | The key is written to the shell's history file and is readable via `ps` by any process for as long as the command runs; neither exposure can be undone afterwards |
| A11 | The compiler and OS leave secrets where the tool can reach them: no swap-out, no core dump, no copy the optimizer keeps alive | Zeroization is best-effort. Key material can survive in swap, in a crash dump, or in a stack copy that `zeroize` never sees |
| A12 | Library callers manage the copies they ask for (`as_bytes`, `to_secret_key`, `expose_bytes`, `expose_str`) | Exported key material outlives the crate's erase-on-drop guarantees. `secp256k1::SecretKey` is `Copy` and its `non_secure_erase` is best-effort by upstream's own documentation |

## Trust boundaries

```text
+---------------------------------------------------+
|  Trusted: this tool's process                     |
|  - Buffers the tool owns are zeroized on drop     |
|  - Best effort only: swap, crash dumps and        |
|    compiler-made copies are out of reach          |
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
- Shell environment (warnings issued about logging, and about passing a key as a
  command-line argument)

## What we cannot erase

Zeroization covers the buffers this process owns. It does not reach:

- Output already written to stdout, the terminal, or whatever consumed it
- The argument list, when the deprecated `--from-hex <HEX>` form is used
- Memory the OS relocated: swap, hibernation images, crash dumps
- Copies libsecp256k1 makes on its own stack while deriving a public key
- Copies the optimizer creates or keeps alive, an inherent limit that the
  [`zeroize`](https://docs.rs/zeroize) crate documents for itself
- Anything a library caller obtained through `as_bytes`, `to_secret_key`, or an
  `expose_*` method

`tests/no_secret_residue.rs` proves the first guarantee for the heap by scanning
every freed block for key material. It cannot observe the stack, so the last
three items above are reasoned about, not measured.
