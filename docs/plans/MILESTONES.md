# Agent Vault Milestones

Date: 2026-06-04

## Current Direction

Build the first working version in Python because this machine can run and test Python now, while Rust/Cargo dependency resolution is blocked by crates.io DNS. The command surface remains `s`. The project is still inspired by `tobi/s`: https://github.com/tobi/s

The implementation must not modify home-server services, firewall rules, system packages, or existing data. All work stays inside `/mnt/DATA/projects/agent-vault` until explicit deployment.

## Cross-cutting: Testing and Agent Documentation

Status: active throughout

Rules:

- Every milestone needs tests or a smoke script before commit.
- Use fake API keys only.
- Agent-facing documentation lives in `docs/AGENT_README.md`.
- The Docker web UI must include a copy button that copies the agent documentation text.
- Agent documentation must explain safe discovery, `S_AGENT_MODE=1`, blocked commands, `s run`, `s cmd run`, archive instead of delete, backup, and troubleshooting.
- Agent documentation must never include real secret values.

## Milestone 1: Working Local CLI

Status: complete

Deliver:

- `s help` and `s help <command>`.
- Encrypted vault file storage.
- `s init`, `s ls`, `s add`, `s update`, `s archive`, `s restore`.
- `s run <KEY...> -- <command>` with env injection and output redaction.
- `s cmd add`, `s cmd ls`, `s cmd run`.
- `s status`, `s doctor`, `s audit`.
- `s backup`.
- Human-only `s get <NAME> --auth` blocked in agent mode.
- Tests with fake API keys only.

Verification completed:

```bash
/mnt/DATA/AIW2/venv/bin/python -m pytest /mnt/DATA/projects/agent-vault/tests
/mnt/DATA/AIW2/venv/bin/python -m agent_vault.cli help
S_VAULT_PATH=/tmp/agent-vault-smoke.senv /mnt/DATA/AIW2/venv/bin/python -m agent_vault.cli doctor
```

Commit when done:

```text
feat: add working local cli
```


## Milestone 1b: CLI Safety Hardening

Status: complete

Deliver:

- Human-only command stubs and behavior for `s export --auth`, `s delete NAME --auth`, `s purge NAME --auth`, `s rollback NAME --to VERSION --auth`, and `s restore-backup FILE --auth`.
- All destructive/raw-read commands refuse in `S_AGENT_MODE=1`.
- All destructive/raw-read commands refuse without an interactive terminal.
- `s import` for `.env` style values without echoing secrets.
- Stronger `s doctor` checks for vault permissions and unsafe server status.
- Tests for non-TTY refusal and agent-mode refusal using fake secrets only.

Verification completed:

```bash
/mnt/DATA/AIW2/venv/bin/python -m pytest /mnt/DATA/projects/agent-vault/tests
/mnt/DATA/AIW2/venv/bin/python -m agent_vault.cli help export
```

Commit:

```text
feat: harden cli safety commands
```


## Milestone 1c: CLI Polish and Edge Cases

Status: complete

Delivered:

- Empty stdin values fail before encryption.
- No-op updates fail clearly.
- Notes require comments.
- Duplicate import keys fail.
- `s history NAME` lists metadata only.
- `s cmd update`, `s cmd archive`, and `s cmd restore` work.
- `s doctor` reports file permissions, parse status, and server status.

Verification completed:

```bash
/mnt/DATA/AIW2/venv/bin/python -m pytest /mnt/DATA/projects/agent-vault/tests
PYTHON=/mnt/DATA/AIW2/venv/bin/python scripts/smoke_cli.sh
```

Commit:

```text
feat: polish cli edge cases
```

## Milestone 2: Docker CLI Packaging

Status: complete

Deliver:

- Dockerfile.
- Docker compose example with `/data/vault.senv`.
- Localhost-only defaults for future server mode.
- Docker smoke test for `s help`, `s init`, `s ls`, and `s run`.

Verification completed:

```bash
scripts/smoke_docker.sh
/mnt/DATA/AIW2/venv/bin/python -m pytest /mnt/DATA/projects/agent-vault/tests
PYTHON=/mnt/DATA/AIW2/venv/bin/python scripts/smoke_cli.sh
```

Commit:

```text
feat: add docker cli packaging
```

## Milestone 3: Server and Web UI Plan Lock

Status: pending

Deliver:

- Final API route plan.
- Security checklist for no public exposure.
- Decision on simple frontend stack.

Commit when done:

```text
chore: lock server ui plan
```

## Milestone 4: Private API and Web UI

Status: complete

Deliver:

- Private API bound to `127.0.0.1` by default.
- Web UI for list, add, update, command registry, backup, audit, and copy agent documentation.
- Human confirmation flow for reveal and destructive actions.
- No raw values in logs.

Verification completed:

```bash
/mnt/DATA/AIW2/venv/bin/python -m pytest /mnt/DATA/projects/agent-vault/tests
PYTHON=/mnt/DATA/AIW2/venv/bin/python scripts/smoke_cli.sh
scripts/smoke_docker.sh
scripts/smoke_web_docker.sh
```

Commit:

```text
feat: add private web ui
```
