#!/usr/bin/env bash
# Lifecycle: init, add, list, exec, unlock/lock, status.
set -euo pipefail

cd "$(dirname "$0")"
S="$(cd .. && cargo build --release -q && echo "$(pwd)/target/release/s")"

WORK=$(mktemp -d); trap "rm -rf $WORK" EXIT
export S_TICKET_DIR="$WORK/tickets"
cd "$WORK"

echo "==> init (picks up this host's ~/.ssh/id_ed25519)"
"$S" init laptop

echo
echo "==> add three secrets (no identity required — only public keys are used)"
"$S" add API_KEY=sk-live-supersecret123
"$S" add DB_URL=postgres://u:p@h/db
"$S" add FOO=bar

echo
echo "==> the YAML file is inspectable:"
cat .senv | head -8
echo "   ..."

echo
echo "==> list (also no identity required)"
"$S" list

echo
echo "==> status"
"$S" status

echo
echo "==> exec — decrypts, injects into env, scrubs echoes. Identity is loaded"
echo "    once, then cached in a 7-day ticket."
"$S" -- bash -c 'echo "API_KEY=$API_KEY  FOO=$FOO"'

echo
echo "==> second exec: uses the ticket, no identity touch"
"$S" -- bash -c 'echo "still scrubbed: $DB_URL"'

echo
echo "==> lock"
"$S" lock
"$S" status
