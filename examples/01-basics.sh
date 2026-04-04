#!/usr/bin/env bash
# Basic lifecycle: add, list, exec, lock, unlock, status.
# Run with a throwaway passphrase via S_PASSPHRASE so it's non-interactive.
set -euo pipefail

cd "$(dirname "$0")"
S="$(cd .. && cargo build --release -q && echo "$(pwd)/target/release/s")"

WORK=$(mktemp -d); trap "rm -rf $WORK" EXIT
export S_TICKET_DIR="$WORK/tickets"
cd "$WORK"

echo "==> add three secrets (first one creates the store)"
S_PASSPHRASE=demo "$S" add API_KEY=sk-live-supersecret123
S_PASSPHRASE=demo "$S" add DB_URL=postgres://u:p@h/db
S_PASSPHRASE=demo "$S" add FOO=bar

echo
echo "==> list"
"$S" list

echo
echo "==> status (note: ticket valid for ~7d)"
"$S" status

echo
echo "==> run a command with the env injected"
"$S" -- bash -c 'echo "API_KEY=$API_KEY  FOO=$FOO"'

echo
echo "==> the same command, but the secret value is scrubbed on echo"
"$S" -- bash -c 'echo "leaking: $API_KEY here, and $DB_URL too"'

echo
echo "==> lock"
"$S" lock
"$S" status

echo
echo "==> after locking, list without a passphrase fails"
"$S" list 2>&1 || true

echo
echo "==> give passphrase again → fresh 7-day ticket"
S_PASSPHRASE=demo "$S" unlock
"$S" status
