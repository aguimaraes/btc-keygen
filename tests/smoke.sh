#!/bin/sh
# Release-artifact smoke test. Runs the actual binary on the target OS.
# Usage: sh tests/smoke.sh <path-to-binary>
# POSIX sh: runs unmodified on Linux, macOS, FreeBSD, and Git Bash (Windows).
set -eu

bin="$1"

# 1. Known-answer test: catches per-target miscompiles that host-side
#    `cargo test` can never see.
out=$("$bin" generate --from-hex \
  0000000000000000000000000000000000000000000000000000000000000001 --json)
echo "$out" | grep -q 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
echo "$out" | grep -q 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'

# 2. OS entropy: the one code path that genuinely differs per OS.
a=$("$bin" generate --json)
b=$("$bin" generate --json)
[ "$a" != "$b" ]
echo "$a" | grep -q '"address":"bc1q'
echo "$b" | grep -q '"wif":"'

# 3. Failure paths exit non-zero.
if "$bin" generate --from-hex notahexkey 2>/dev/null; then
  echo "FAIL: invalid --from-hex input must exit non-zero" >&2
  exit 1
fi
if "$bin" nonsense-subcommand 2>/dev/null; then
  echo "FAIL: unknown subcommand must exit non-zero" >&2
  exit 1
fi

echo "smoke: OK ($bin)"
