#!/usr/bin/env bash
# Demonstrate output scrubbing, including a secret printed byte-by-byte
# (which tests the sliding-window straddle logic in scrub.rs).
set -euo pipefail

cd "$(dirname "$0")"
S="$(cd .. && cargo build --release -q && echo "$(pwd)/target/release/s")"

WORK=$(mktemp -d); trap "rm -rf $WORK" EXIT
export S_TICKET_DIR="$WORK/tickets"
cd "$WORK"

S_PASSPHRASE=demo "$S" add TOKEN=abcdef1234567890XYZ

echo "==> plain echo: scrubbed"
"$S" -- sh -c 'echo "token is $TOKEN right here"'

echo
echo "==> printed one byte at a time with delay: still scrubbed"
"$S" -- bash -c '
for ((i=0; i<${#TOKEN}; i++)); do
  printf "%s" "${TOKEN:$i:1}"
  sleep 0.01
done
echo'

echo
echo "==> goes to stderr too"
"$S" -- sh -c 'echo "oops $TOKEN" >&2'

echo
echo "==> non-zero exit is propagated"
"$S" -- sh -c "exit 42" || echo "caller saw exit=$?"
