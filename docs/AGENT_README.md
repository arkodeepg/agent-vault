# Agent Vault: Agent Integration README

This file is safe to give to coding agents, CLI agents, OpenCode, Codex, Claude Code, and other local automation tools. It explains how to use Agent Vault without exposing raw secrets.

## Core Rule

Agents must never request, print, export, log, or store raw secret values.

Use Agent Vault to discover safe metadata and run commands with injected env vars. Secret values should stay inside Agent Vault and subprocess environments only.

## Required Agent Mode

When an agent runs Agent Vault commands, set:

```bash
S_AGENT_MODE=1
```

Agent mode blocks raw reveal and destructive operations.

Blocked in agent mode:

```bash
s get
s export
s delete
s purge
s rollback
s restore-backup
s password change
```

Allowed in agent mode:

```bash
s help
s ls
s add
s update
s archive
s restore
s run
s cmd ls
s cmd add
s cmd update
s cmd archive
s cmd restore
s cmd run
s import
s backup
s status
s doctor
s audit
s history
```

## Discover Available Secrets and Commands

Use:

```bash
S_AGENT_MODE=1 s ls
S_AGENT_MODE=1 s ls --json
S_AGENT_MODE=1 s cmd ls
```

These commands show safe metadata only:

- name
- type
- comment
- tags
- command dependencies
- archive status
- timestamps

They do not show raw values.

## Run a Script With a Secret

Use `s run` and pass secret names before `--`:

```bash
S_AGENT_MODE=1 s run OPENAI_API_KEY -- python3 script.py
```

Inside Python:

```python
import os
api_key = os.environ["OPENAI_API_KEY"]
```

If the script prints the secret, Agent Vault redacts it from stdout and stderr as `[REDACTED]`.

## Run a Stored Command

Use:

```bash
S_AGENT_MODE=1 s cmd run COMMAND_NAME
```

The stored command declares which secrets it needs. Agent Vault injects those secrets and redacts output.

## Add or Update Secrets

If the user explicitly gives a new value or a process pipes one in, use stdin. Do not echo the value.

```bash
printf '%s' "$VALUE" | S_AGENT_MODE=1 s add API_KEY --stdin --comment "What this key is for" --tags api
```

Update a value:

```bash
printf '%s' "$VALUE" | S_AGENT_MODE=1 s update API_KEY --stdin
```

Update metadata only:

```bash
S_AGENT_MODE=1 s update API_KEY --comment "Updated safe explanation" --tags api,client
```

## Do Not Delete

Agents should archive instead of deleting:

```bash
S_AGENT_MODE=1 s archive OLD_KEY
```

Restore if needed:

```bash
S_AGENT_MODE=1 s restore OLD_KEY
```

Permanent delete is human-only.

## Import .env Text

Use stdin to avoid printing values:

```bash
S_AGENT_MODE=1 s import --stdin < .env
```

Never paste imported values into chat after import.

## Backup

Backups copy encrypted vault data only. They do not decrypt values.

```bash
S_AGENT_MODE=1 s backup --to ./backups
```

## Troubleshooting

```bash
S_AGENT_MODE=1 s status
S_AGENT_MODE=1 s doctor
S_AGENT_MODE=1 s help
S_AGENT_MODE=1 s help run
```

## Security Checklist for Agents

Before using Agent Vault, confirm:

- `S_AGENT_MODE=1` is set.
- You use `s ls` to discover, not `s get`.
- You use `s run` or `s cmd run` to use secrets.
- You never ask the user to paste raw secrets unless they are intentionally adding or updating a value.
- You never print env vars that may contain secrets.
- You archive instead of deleting.
- You do not upload vault files or backups to third-party services.
