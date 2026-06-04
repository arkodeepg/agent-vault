#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
CID=""
cleanup(){ if [[ -n "$CID" ]]; then docker rm -f "$CID" >/dev/null 2>&1 || true; fi; rm -rf "$TMP"; }
trap cleanup EXIT

cd "$ROOT"
docker build -t agent-vault:local . >/dev/null
docker run --rm -v "$TMP:/data" -e S_KEY=test-password agent-vault:local init >/dev/null
CID="$(docker run -d -p 127.0.0.1:8787:8787 -v "$TMP:/data" -e S_KEY=test-password agent-vault:local web --host 0.0.0.0 --port 8787)"
for _ in {1..30}; do
  if curl -fsS http://127.0.0.1:8787/ >/tmp/agent-vault-web.html; then break; fi
  sleep 0.5
done
grep 'color-scheme: dark' /tmp/agent-vault-web.html >/dev/null
grep 'Copy agent docs' /tmp/agent-vault-web.html >/dev/null
curl -fsS http://127.0.0.1:8787/api/agent-docs | grep 'S_AGENT_MODE=1' >/dev/null
echo "agent-vault docker web smoke ok"
