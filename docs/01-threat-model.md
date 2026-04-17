# Threat Model

## Assets under protection

| Asset | Location | Lifetime |
|---|---|---|
| Private key bytes (32 bytes) | Process memory only | Single execution |
| WIF-encoded private key | Process memory, then stdout | Single execution |
| Public key | Process memory, then stdout | Single execution; not secret but integrity-critical |

## Threats

### T1 — Weak or predictable entropy

**Risk:** If the CSPRNG is broken, biased, or seeded from a low-entropy source,
generated private keys are guessable.

**Mitigation:** Use only OS-provided CSPRNG (`getrandom` syscall on Linux,
equivalent on other platforms). Never seed from userspace clocks, PIDs, or other
predictable values. Never implement a custom PRNG.

**Residual risk:** We trust the OS kernel's entropy pool. On a freshly booted
air-gapped VM with no hardware RNG, entropy may be low. This is documented as an
operator responsibility.

### T2 — Private key outside valid secp256k1 range

**Risk:** A 32-byte random value may be 0 or >= curve order `n`
(`0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`). Such a
key is invalid and could produce undefined behavior in downstream EC operations.

**Mitigation:** Validate the key is in `[1, n-1]` before use. Reject and
regenerate if out of range.

**Residual risk:** Negligible — probability of a random 256-bit value falling
outside the valid range is approximately 3.73 * 10^-39.

### T3 — Secret material persisted to disk

**Risk:** Private key written to a file, log, temp file, config, core dump, or
swap.

**Mitigation:** Never write secrets to any file. Use `zeroize` on secret buffers
when dropped. Document that the operator should disable core dumps and consider
encrypted swap or no swap on the air-gapped machine.

**Residual risk:** We cannot prevent the OS from paging process memory to swap.
This is an operator-level concern documented in usage guidance.

### T4 — Secret material leaked via side channels

**Risk:** Timing attacks, cache attacks, or speculative execution attacks during
EC operations.

**Mitigation:** Delegate EC math to `libsecp256k1` (via the `secp256k1` crate),
which is designed with constant-time operations. Do not implement EC math
ourselves.

**Residual risk:** We inherit the side-channel properties of the underlying
library. This is acceptable — `libsecp256k1` is the most reviewed implementation
in the Bitcoin ecosystem.

### T5 — Supply chain compromise of dependencies

**Risk:** A malicious crate version exfiltrates key material or weakens entropy.

**Mitigation:** Minimize dependency count. Pin exact versions. Audit dependency
tree. Each dependency must be justified. Use `cargo audit`. The tool has no
network capability, which limits exfiltration vectors even if a dependency is
compromised.

**Residual risk:** A compromised dependency could weaken key generation in a way
that is not immediately detectable (e.g., biased output). Mitigation is small
dependency surface plus code review.

### T6 — User loses secret output

**Risk:** The user runs the tool, captures only the address, sends funds, and
then cannot spend them because the private key was never saved.

**Mitigation:** Default output always includes both address and WIF. Warnings on
stderr explain the one-time nature. The tool never implies secrets can be
recovered.

**Residual risk:** User ignores warnings. This is a UX problem, not a code
problem. We mitigate as far as possible through clear messaging.

### T7 — User confuses keypairs across runs

**Risk:** User runs the tool twice, mixes up which WIF goes with which address.

**Mitigation:** Output address and WIF together in a single atomic block per run.
Each run outputs exactly one keypair. Warnings state each run generates a new,
independent keypair.

### T8 — Process memory inspection by co-located attacker

**Risk:** Another process on the same machine reads `/proc/<pid>/mem` or attaches
a debugger.

**Mitigation:** This tool is designed for air-gapped, single-user machines.
Zeroize secrets on drop to minimize the window. Document that the machine should
be trusted and single-user.

**Residual risk:** A root-level attacker on the same machine can read process
memory. Out of scope — the air-gapped machine must be trusted.

### T9 — Incorrect encoding (WIF, Bech32)

**Risk:** A bug in WIF or Bech32 encoding produces an address or key that looks
valid but is wrong, leading to funds locked in an unspendable address.

**Mitigation:** Test against published test vectors from BIP173 and the Bitcoin
wiki. Use known-answer tests with deterministic inputs.

### T10 — Weak user-provided private key (`--from-hex`)

**Risk:** When the caller passes `--from-hex`, the tool uses the provided 32
bytes directly as the private key. If those bytes came from a low-entropy source
(a short passphrase, a predictable pattern, a biased physical process), the
resulting key is guessable.

**Mitigation:** Validate that the input is a valid secp256k1 scalar. Document on
the website and in `--help` that the security of the generated key depends
entirely on the quality of the user-provided bytes, and that the OS CSPRNG is
bypassed in this mode.

**Residual risk:** Key quality is the caller's responsibility. The tool cannot
detect low-entropy input. This mode exists so the operator can supply their own
entropy source (for example, dice or coin flips converted to hex); misuse is an
operator concern.

## Operator responsibilities

The following are outside the tool's control and must be handled by the operator:

- Ensure the machine has adequate entropy (hardware RNG or sufficient boot-time
  entropy)
- Run the tool on a trusted, air-gapped, single-user machine
- Disable core dumps (`ulimit -c 0`)
- Use encrypted swap or disable swap entirely
- Do not run the tool in environments that log stdout (e.g., `script`, shell
  audit logging)
- Securely store the output (paper, encrypted volume, etc.)
- Verify the tool's integrity before use (checksum, signature)
