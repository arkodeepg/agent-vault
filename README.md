# Agent Vault

Agent Vault is a password manager for AI agents. Agents can discover safe metadata and run scripts with injected secrets, but they do not get to see raw API keys, passwords, env values, or exported secret data.

## Planned Modes

- CLI-only mode: install the `s` binary and use it directly from a terminal or agent workflow.
- Docker/server mode: run a private container on the home server with a mounted encrypted vault and web UI.
- Hybrid mode: use the same encrypted vault from both the CLI and Docker safely.

## Installation And First Run

Run from this checkout:

```bash
PYTHONPATH="$PWD" python3 -m agent_vault.cli version
PYTHONPATH="$PWD" python3 -m agent_vault.cli init
PYTHONPATH="$PWD" python3 -m agent_vault.cli password change --auth
```

Or use the wrapper:

```bash
bin/s version
bin/s init
bin/s password change --auth
```

Important setup default:

- The default master key is `password`.
- Change it immediately to a strong master key with `s password change --auth` or the dashboard `Master key` tab.
- `s init` prints recovery codes once. Store them somewhere separate from `vault.senv`, `master.json`, and normal backups.
- If you lose the master key and all recovery codes, the vault cannot be recovered.

Docker first run:

```bash
docker compose up --build
```

Then open the dashboard, unlock with `password`, and change the master key immediately.

## Data Storage

The default source of truth is two local files on disk:

```text
vault.senv      encrypted vault data
master.json     password verifier, wrapped vault key, and recovery-code metadata
```

`master.json` does not store the raw master key. The master key unlocks a random vault encryption key, and that vault key decrypts `vault.senv`.

## Default Master Key

The default master key is `password`. Change it immediately during setup.

Change it from the web dashboard under `Master key`, or from the CLI:

```bash
s password change --auth
```

Changing the master key rewraps the vault key. It does not write the raw master key to disk.

During first setup and during `s migrate-key`, Agent Vault prints recovery codes once. Store them somewhere separate from the vault. If you forget the master key and lose all recovery codes, the vault is intentionally unrecoverable.

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

Secret values, command values, and value history are encrypted. Default `s ls` output shows only names and comments. Structured `s ls --json` output can include additional safe metadata for agent discovery. Raw secret values must never appear in normal logs, list output, or agent context.

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
s status
s doctor
s audit
s backup
s version
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
s migrate-key
s recovery rotate --auth
s recovery use
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

Commands:

```bash
s backup
s backup --to /path/to/backups
s restore-backup <BACKUP_FILE> --auth
```

Back up `vault.senv` and `master.json` together. Store recovery codes separately from both files.

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
- Do not store recovery codes beside the vault backup.

More detail: [Security Model](docs/SECURITY.md), [CLI Usage](docs/CLI.md), [Docker Usage](docs/DOCKER.md), [Web UI](docs/WEB.md), [Agent README](docs/AGENT_README.md).

## Agent Documentation

Safe agent-facing usage docs live at `docs/AGENT_README.md`. The Docker web UI should include a copy button for this file.

## Local Smoke Test

```bash
PYTHON=/mnt/DATA/AIW2/venv/bin/python scripts/smoke_cli.sh
```
