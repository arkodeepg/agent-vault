#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export PYTHONPATH="$ROOT"
export S_KEY="test-password"
export S_VAULT_PATH="$TMP/vault.senv"
FAKE="test_sk_1234567890abcdef_FAKE_ONLY"
PY="${PYTHON:-python3}"

$PY -m agent_vault.cli help >/dev/null
$PY -m agent_vault.cli init >/dev/null
printf '%s' "$FAKE" | $PY -m agent_vault.cli add TEST_API_KEY --stdin --comment "Fake key for smoke test" --tags api,test >/dev/null
$PY -m agent_vault.cli ls --json | grep TEST_API_KEY >/dev/null
OUT="$($PY -m agent_vault.cli run TEST_API_KEY -- "$PY" -c 'import os; print(os.environ["TEST_API_KEY"])')"
if [[ "$OUT" != "[REDACTED]" ]]; then
  echo "expected redacted output, got: $OUT" >&2
  exit 1
fi
$PY -m agent_vault.cli backup --to "$TMP/backups" >/dev/null
S_AGENT_MODE=1 $PY -m agent_vault.cli get TEST_API_KEY --auth >/tmp/agent-vault-smoke.err 2>&1 && {
  echo "agent-mode get unexpectedly succeeded" >&2
  exit 1
}
grep 'agent mode' /tmp/agent-vault-smoke.err >/dev/null

echo "agent-vault smoke ok"
