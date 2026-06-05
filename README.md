# Agent Vault

Agent Vault is a password manager and secure API execution layer for AI agents. Agents can discover safe metadata and ask Agent Vault to perform authenticated API requests, but they must not receive raw API keys, passwords, env values, or exported secret data.

Core thesis:

```text
Agents may use API-backed capabilities, but agents must never receive, read, print, store, or pass around raw API credentials.
```

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
s api ls
s api add <PROFILE> --from profile.json
s api request <PROFILE> --method GET --url https://api.example.com/path
s api pending
s api approve <REQUEST_ID>
s api reject <REQUEST_ID>
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

Human/manual commands can still use raw injection when intentionally needed:

```bash
s api request OPENAI_PROFILE --method GET --url https://api.openai.com/v1/models
```

```python
from agent_vault.client import api_request

models = api_request(
    profile="OPENAI_PROFILE",
    method="GET",
    url="https://api.openai.com/v1/models",
)
```

For agent-run scripts, prefer the API request layer or client library. `s run` is a human/manual escape hatch because it gives the subprocess a raw secret.

Agent HTTP API clients require:

```bash
AGENT_VAULT_URL=http://100.97.39.56:8787
AGENT_VAULT_TOKEN=...
```

The server receives `AGENT_VAULT_TOKEN` as `S_AGENT_API_TOKEN` and uses it only to authorize API execution requests.

## Domain Approval Flow

API profiles include approved hosts. If an agent or script asks Agent Vault to call a new host, the request is blocked before credentials are injected and a pending domain approval is recorded.

Approve or reject pending hosts from the dashboard `API Profiles` tab or from the CLI:

```bash
s api pending
s api approve REQUEST_ID
s api reject REQUEST_ID
```

Path changes on an already approved host can be handled by scripts. Host changes need approval once.

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
Threat model: [Agent Vault Threat Model](docs/THREAT_MODEL.md).

## Agent Documentation

Safe agent-facing usage docs live at `docs/AGENT_README.md`. The Docker web UI should include a copy button for this file.

## Local Smoke Test

```bash
PYTHON=/mnt/DATA/AIW2/venv/bin/python scripts/smoke_cli.sh
```
