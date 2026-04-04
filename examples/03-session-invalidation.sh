#!/usr/bin/env bash
# Show all the ways a session ticket becomes invalid:
#   1. explicit `s lock`
#   2. tampering with the ticket file (AEAD auth fails)
#   3. deleting the ticket file
#   4. tampering with expiry field (AAD-bound → auth fails)
#
# We can't actually reboot in a demo; a reboot is equivalent to case 2,
# because after reboot boot_id differs and derives a different TK that
# won't authenticate the ticket's ciphertext.
set -euo pipefail

cd "$(dirname "$0")"
S="$(cd .. && cargo build --release -q && echo "$(pwd)/target/release/s")"

WORK=$(mktemp -d); trap "rm -rf $WORK" EXIT
export S_TICKET_DIR="$WORK/tickets"
cd "$WORK"

S_PASSPHRASE=demo "$S" add SECRET=hunter2value

echo "==> 1. explicit lock"
"$S" list
"$S" lock
echo "    list without passphrase after lock:"
"$S" list 2>&1 || true

echo
echo "==> 2. tamper with ticket ciphertext (AEAD auth fails → ticket deleted)"
S_PASSPHRASE=demo "$S" unlock
TICKET=$(ls "$S_TICKET_DIR"/*.ticket)
dd if=/dev/urandom of="$TICKET" bs=1 count=1 seek=80 conv=notrunc 2>/dev/null
"$S" list 2>&1 || true
echo "    ticket after tamper: $(ls "$S_TICKET_DIR"/*.ticket 2>/dev/null || echo '(removed by s)')"

echo
echo "==> 3. ticket file deleted externally"
S_PASSPHRASE=demo "$S" unlock
rm "$S_TICKET_DIR"/*.ticket
"$S" list 2>&1 || true

echo
echo "==> 4. tamper with expiry field (covered by AAD → auth fails → deleted)"
S_PASSPHRASE=demo "$S" unlock
TICKET=$(ls "$S_TICKET_DIR"/*.ticket)
# expiry_boot_ns sits at offset MAGIC(6) + SALT(32) + NONCE(12) = 50
printf '\xff\xff\xff\xff\xff\xff\xff\xff' | dd of="$TICKET" bs=1 count=8 seek=50 conv=notrunc 2>/dev/null
"$S" list 2>&1 || true
echo "    ticket after tamper: $(ls "$S_TICKET_DIR"/*.ticket 2>/dev/null || echo '(removed by s)')"
