#!/usr/bin/env bash
# Overwrite behaviour: `-f` forces, otherwise we prompt on /dev/tty (and
# fail-closed when there is no TTY, as in this example).
set -euo pipefail

cd "$(dirname "$0")"
S="$(cd .. && cargo build --release -q && echo "$(pwd)/target/release/s")"

WORK=$(mktemp -d); trap "rm -rf $WORK" EXIT
export S_TICKET_DIR="$WORK/tickets"
cd "$WORK"

"$S" init demo
"$S" add API_KEY=first-value
echo
echo "==> attempting to overwrite without -f and no TTY → refused"
"$S" add API_KEY=second-value < /dev/null 2>&1 || echo "(expected failure)"

echo
echo "==> -f overwrites"
"$S" add -f API_KEY=second-value
"$S" -- sh -c 'echo "value=$API_KEY"'

echo
echo "==> adding a new key never prompts"
"$S" add OTHER=ok
"$S" list
