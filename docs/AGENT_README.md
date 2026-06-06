# Agent Guide

This file is safe to give to coding agents, CLI agents, OpenCode, Codex, Claude Code, and other local automation tools.

## Non-Negotiable Rule

Agents must never request, print, export, log, store, or receive raw secret values.

Use Agent Vault for safe metadata and brokered API calls only.

## Required Mode

Set:

```bash
S_AGENT_MODE=1
```

Agent mode blocks raw reveal, export, destructive actions, and raw secret injection.

## Safe Discovery

```bash
S_AGENT_MODE=1 s ls
S_AGENT_MODE=1 s ls --json
S_AGENT_MODE=1 s api ls
```

These commands show safe metadata only:

- name
- type
- comment
- tags
- dependency names
- archive status

They do not show raw values.

## Safe API Use

```bash
S_AGENT_MODE=1 s api request PROFILE \
  --method GET \
  --url https://api.example.com/path
```

Agent Vault checks the API profile, verifies the host, injects credentials internally, sends the request, and returns the response.

Python scripts should use the client library:

```python
from agent_vault.client import api_request

response = api_request(
    profile="BASECAMP",
    method="GET",
    url="https://3.basecampapi.com/example.json",
)
```

For HTTP client usage, set `AGENT_VAULT_URL` plus either `AGENT_VAULT_TOKEN` or `S_AGENT_API_TOKEN`.

## Pending Domains

If the URL host is not approved, Agent Vault blocks the request and creates a pending approval.

```bash
S_AGENT_MODE=1 s api pending
```

Agents must not work around this. The user approves or rejects the host from the dashboard or CLI.

## Adding Values

Only add or update a value when the user explicitly provides it.

```bash
printf '%s' "$VALUE" | S_AGENT_MODE=1 s add API_KEY --stdin --comment "What this key is for"
printf '%s' "$VALUE" | S_AGENT_MODE=1 s update API_KEY --stdin
```

Never echo the value.

## Blocked For Agents

Do not use:

```bash
s get
s run KEY -- command
s export
s delete
s purge
s rollback
s restore-backup
s password change
s recovery rotate
s recovery use
```

Use `archive` instead of delete:

```bash
S_AGENT_MODE=1 s archive OLD_KEY
```

## Checklist

- Use `S_AGENT_MODE=1`.
- Discover with `s ls` or `s api ls`.
- Call APIs with `s api request` or `agent_vault.client`.
- Treat unapproved domains as blocked.
- Never print environment variables that may contain secrets.
- Never upload vault files or backups.
