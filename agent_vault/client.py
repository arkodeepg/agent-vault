from __future__ import annotations

import json
import os
import urllib.request
from typing import Any


class AgentVaultClientError(RuntimeError):
    pass


def api_request(
    profile: str,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: Any = None,
    vault_url: str | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """Call Agent Vault's agent API request endpoint without exposing raw keys."""
    base = (vault_url or os.environ.get("AGENT_VAULT_URL") or "http://100.97.39.56:8787").rstrip("/")
    agent_token = token or os.environ.get("AGENT_VAULT_TOKEN") or os.environ.get("S_AGENT_API_TOKEN")
    if not agent_token:
        raise AgentVaultClientError("AGENT_VAULT_TOKEN or S_AGENT_API_TOKEN is required")
    payload = {
        "profile": profile,
        "method": method,
        "url": url,
        "headers": headers or {},
        "body": body,
    }
    req = urllib.request.Request(
        f"{base}/api/agent/request",
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "content-type": "application/json",
            "x-agent-vault-token": agent_token,
        },
    )
    with urllib.request.urlopen(req, timeout=60) as res:
        return json.loads(res.read().decode())
