# Agent Vault

Agent Vault is a single-user internal secret and command vault for AI-assisted workflows. It is inspired by `s` from Tobi Lutke: https://github.com/tobi/s

The goal is simple: agents should be able to discover and use secrets without seeing raw API keys, passwords, env values, or exported secret data.

## Planned Modes

- CLI-only mode: install the `s` binary and use it directly from a terminal or agent workflow.
- Docker/server mode: run a private container on the home server with a mounted encrypted vault and web UI.
- Hybrid mode: use the same encrypted vault from both the CLI and Docker safely.

## Data Storage

The default source of truth is one encrypted vault file on disk.

## Default Master Key

The default master key is `password`. Please change it for fuck's sake.

Change it from the web dashboard under `Master key`, or from the CLI:

```bash
s password change --auth
```

Changing the master key re-encrypts existing values and value history, then writes the new key to the configured password file. For Docker, use `S_KEY_FILE=/data/master.key` so the dashboard can update it.


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

Secret values, command values, and value history are encrypted. Safe metadata such as names, comments, tags, timestamps, and the last three characters of the value can be listed for agent discovery. Raw secret values must never appear in normal logs, list output, or agent context.

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
s password change --auth
```

Human-only commands require an interactive confirmation flow and the current master key. The master key must not be passed as a visible command argument.

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
s password change --auth
```

## CSV Export

The web dashboard has an `Export CSV` button. It asks for the current master key before generating a CSV file with active items. The export uses real CSV quoting, so comments with commas, quotes, or newlines remain valid.

## Security Defaults

- Single-user internal use only in v1.
- Server binds to `127.0.0.1` by default.
- No public exposure by default.
- Web metadata and mutation APIs require the master key through the dashboard unlock flow.
- Agent mode blocks reveal, export, delete, purge, rollback, and restore operations.
- Permanent delete is never available to agents.
- Raw secret reveal always requires human presence.
- Dashboard master key rotation requires the current key and is blocked in agent mode.
- The web UI has no multi-user auth in v1. Keep it private on localhost or Tailscale only.
- Do not back up `master.key` with `vault.senv` unless you intentionally want the backup to be self-decrypting.

## Agent Documentation

Safe agent-facing usage docs live at `docs/AGENT_README.md`. The Docker web UI should include a copy button for this file.

## Local Smoke Test

```bash
PYTHON=/mnt/DATA/AIW2/venv/bin/python scripts/smoke_cli.sh
```

## Development Plan

See `docs/plans/2026-06-04-agent-vault-plan.md` and `docs/plans/MILESTONES.md`. Docker web UI notes live at `docs/WEB.md`.
