# Agent Vault

Agent Vault is a single-user internal secret and command vault for AI-assisted workflows. It is inspired by `s` from Tobi Lutke: https://github.com/tobi/s

The goal is simple: agents should be able to discover and use secrets without seeing raw API keys, passwords, env values, or exported secret data.

## Planned Modes

- CLI-only mode: install the `s` binary and use it directly from a terminal or agent workflow.
- Docker/server mode: run a private container on the home server with a mounted encrypted vault and web UI.
- Hybrid mode: use the same encrypted vault from both the CLI and Docker safely.

## Data Storage

The default source of truth is one encrypted vault file on disk.

Recommended paths:

```text
CLI local:       ~/.config/agent-vault/vault.senv
Project local:   ./.senv
Docker server:   /data/vault.senv
```

The vault path can be overridden:

```bash
S_VAULT_PATH=/path/to/vault.senv s ls
```

Secret values, command values, and value history are encrypted. Safe metadata such as names, comments, tags, and timestamps can be listed for agent discovery. Raw secret values must never appear in normal logs, list output, or agent context.

## Current CLI Command Surface

Safe agent-facing commands currently implemented:

```bash
s help
s help <command>
s init
s ls
s add <NAME>
s update <NAME>
s archive <NAME>
s restore <NAME>
s run <NAME> [NAME...] -- <command>
s cmd ls
s cmd add <COMMAND_NAME> --uses API_KEY --comment "..." -- <command>
s cmd update <COMMAND_NAME>
s cmd run <COMMAND_NAME>
s scan
s status
s doctor
s audit
s backup
```

Human-only commands currently implemented:

```bash
s get <NAME> --auth
s export --auth
s delete <NAME> --auth
s purge <NAME> --auth
s rollback <NAME> --to <VERSION> --auth
s restore-backup <BACKUP_FILE> --auth
```

Human-only commands require an interactive confirmation flow. The master password must not be passed as a visible command argument.

## Python Usage

Agent Vault injects secrets as environment variables, so Python works normally:

```bash
s run OPENAI_API_KEY -- venv/bin/python execution/example.py
```

```python
import os
api_key = os.environ["OPENAI_API_KEY"]
```

If a script accidentally prints the key, Agent Vault should redact it from stdout and stderr.

## Backup

Backups copy encrypted vault data only. They must not decrypt secret values.

Planned commands:

```bash
s backup
s backup --to /path/to/backups
s restore-backup <BACKUP_FILE> --auth
```

## Security Defaults

- Single-user internal use only in v1.
- Server binds to `127.0.0.1` by default.
- No public exposure by default.
- Agent mode blocks reveal, export, delete, purge, rollback, and restore operations.
- Permanent delete is never available to agents.
- Raw secret reveal always requires human presence.

## Agent Documentation

Safe agent-facing usage docs live at `docs/AGENT_README.md`. The Docker web UI should include a copy button for this file.

## Local Smoke Test

```bash
PYTHON=/mnt/DATA/AIW2/venv/bin/python scripts/smoke_cli.sh
```

## Development Plan

See `docs/plans/2026-06-04-agent-vault-plan.md` and `docs/plans/MILESTONES.md`. Docker web UI notes live at `docs/WEB.md`.
