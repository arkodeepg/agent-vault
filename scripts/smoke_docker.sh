#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cd "$ROOT"
docker build -t agent-vault:local . >/dev/null
docker run --rm agent-vault:local help >/dev/null
docker run --rm -v "$TMP:/data" -e S_KEY=test-password agent-vault:local init >/dev/null
printf 'test_sk_1234567890abcdef_FAKE_ONLY' | docker run --rm -i -v "$TMP:/data" -e S_KEY=test-password agent-vault:local add TEST_API_KEY --stdin --comment "Fake Docker key" >/dev/null
docker run --rm -v "$TMP:/data" -e S_KEY=test-password agent-vault:local ls --json | grep TEST_API_KEY >/dev/null
OUT="$(docker run --rm -v "$TMP:/data" -e S_KEY=test-password agent-vault:local run TEST_API_KEY -- python -c 'import os; print(os.environ["TEST_API_KEY"])')"
if [[ "$OUT" != "[REDACTED]" ]]; then
  echo "expected redacted Docker output, got: $OUT" >&2
  exit 1
fi
docker run --rm -v "$TMP:/data" -e S_AGENT_MODE=1 -e S_KEY=test-password agent-vault:local get TEST_API_KEY --auth >/tmp/agent-vault-docker-smoke.err 2>&1 && {
  echo "agent-mode get unexpectedly succeeded in Docker" >&2
  exit 1
}
grep 'agent mode' /tmp/agent-vault-docker-smoke.err >/dev/null

echo "agent-vault docker smoke ok"
