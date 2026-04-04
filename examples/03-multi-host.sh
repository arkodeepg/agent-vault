#!/usr/bin/env bash
# Multi-host: authorize a second SSH key, decrypt from either, then revoke.
set -euo pipefail

cd "$(dirname "$0")"
S="$(cd .. && cargo build --release -q && echo "$(pwd)/target/release/s")"

WORK=$(mktemp -d); trap "rm -rf $WORK" EXIT
export S_TICKET_DIR="$WORK/tickets"
cd "$WORK"

# This host's identity (whatever ~/.ssh/id_ed25519 points at)
"$S" init laptop
"$S" add TOKEN=hunter2value

# Mint a second identity — imagine it's an agent machine's key
ssh-keygen -t ed25519 -N "" -C "agent@box" -f "$WORK/agent-key" -q
echo
echo "==> authorize the agent host; re-wraps all existing values for both hosts"
"$S" hosts add agent "$WORK/agent-key.pub"
"$S" hosts

echo
echo "==> decrypt using the agent's identity"
S_IDENTITY="$WORK/agent-key" "$S" -- bash -c 'echo "value=$TOKEN"'

echo
echo "==> still works with the laptop identity too"
"$S" lock
"$S" -- bash -c 'echo "value=$TOKEN"'

echo
echo "==> revoke the agent: removes the host AND invalidates any cached ticket"
echo "    on THIS machine (via hosts-digest binding). Agent's ticket, if any,"
echo "    would also fail next use because its wrapping was rotated."
"$S" hosts remove agent
"$S" status

echo
echo "==> agent identity can no longer decrypt"
S_IDENTITY="$WORK/agent-key" "$S" lock
S_IDENTITY="$WORK/agent-key" "$S" -- echo unreachable 2>&1 || echo "(expected failure)"
