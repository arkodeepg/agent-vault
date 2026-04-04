#!/usr/bin/env bash
# `s` refuses to overwrite an existing key: the store is append-only.
set -euo pipefail

cd "$(dirname "$0")"
S="$(cd .. && cargo build --release -q && echo "$(pwd)/target/release/s")"

WORK=$(mktemp -d); trap "rm -rf $WORK" EXIT
export S_TICKET_DIR="$WORK/tickets"
cd "$WORK"

S_PASSPHRASE=demo "$S" add API_KEY=first-value
echo
echo "==> attempting to overwrite → refused"
S_PASSPHRASE=demo "$S" add API_KEY=second-value 2>&1 || echo "(expected failure)"

echo
echo "==> adding a new key is fine"
S_PASSPHRASE=demo "$S" add OTHER=ok
"$S" list
