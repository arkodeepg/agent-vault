# CLI Usage

Use the wrapper:

```bash
bin/s help
```

Or run from the checkout:

```bash
PYTHONPATH="$PWD" python3 -m agent_vault.cli help
```

## Setup

```bash
s init
s password change --auth
s recovery rotate --auth
```

Default master key: `password`. Change it immediately.

Vault path:

```bash
export S_VAULT_PATH=/path/to/vault.senv
```

If omitted, Agent Vault uses `./.senv` when present, otherwise `~/.config/agent-vault/vault.senv`.

## Common Commands

```bash
s ls
s ls --json
s add NAME --stdin --comment "What this is for"
s update NAME --comment "Updated note"
s archive NAME
s restore NAME
s backup --to ./backups
s status
s doctor
```

## API Profiles

```bash
s api ls
s api add PROFILE --from profile.json
s api request PROFILE --method GET --url https://api.example.com/path
```

Domain approvals:

```bash
s api pending
s api pending --all
s api approve REQUEST_ID
s api reject REQUEST_ID
```

Unapproved hosts are blocked before credentials are injected.

## Agent Mode

```bash
S_AGENT_MODE=1 s ls
S_AGENT_MODE=1 s api ls
S_AGENT_MODE=1 s api request PROFILE --method GET --url https://api.example.com/path
```

These must fail in agent mode:

```bash
S_AGENT_MODE=1 s get NAME --auth
S_AGENT_MODE=1 s run NAME -- python3 script.py
```

## Human-Only Commands

These require an interactive terminal and `--auth`:

```bash
s get NAME --auth
s export --auth
s delete NAME --auth
s purge NAME --auth
s rollback NAME --to 1 --auth
s restore-backup FILE --auth
s password change --auth
s recovery rotate --auth
s recovery use
```
