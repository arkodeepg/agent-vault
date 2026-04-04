#!/usr/bin/env bash
# `s import NAME` copies the current value of $NAME from your shell's
# environment into the encrypted store. Useful when you've already got
# secrets loaded (e.g. via direnv, a .envrc, or `set -a; . .env`).
set -euo pipefail

cd "$(dirname "$0")"
S="$(cd .. && cargo build --release -q && echo "$(pwd)/target/release/s")"

WORK=$(mktemp -d); trap "rm -rf $WORK" EXIT
export S_TICKET_DIR="$WORK/tickets"
cd "$WORK"

export OPENAI_API_KEY="sk-proj-abc123xyz"
export GITHUB_TOKEN="ghp_deadbeefcafef00d"

echo "==> import two values from the current shell env"
S_PASSPHRASE=demo "$S" import OPENAI_API_KEY
"$S" import GITHUB_TOKEN
"$S" list

echo
echo "==> values round-tripped correctly, but scrubbed on echo"
"$S" -- bash -c 'echo "openai=$OPENAI_API_KEY github=$GITHUB_TOKEN"'

echo
echo "==> importing a non-existent var fails"
"$S" import NOT_SET 2>&1 || echo "(expected failure)"

echo
echo "==> -f overwrites an existing key from a rotated env var"
export OPENAI_API_KEY="sk-proj-rotated-key"
"$S" import OPENAI_API_KEY -f
"$S" -- bash -c 'echo "new=$OPENAI_API_KEY"'
