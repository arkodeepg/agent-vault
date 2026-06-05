# CLI Usage

Run from the project without installing:

```bash
PYTHONPATH=/mnt/DATA/projects/agent-vault python3 -m agent_vault.cli help
```

Or use the wrapper:

```bash
/mnt/DATA/projects/agent-vault/bin/s help
```

## Default master key

The default master key is `password`. Change it immediately with `s password change --auth` or the `Master key` tab in the dashboard.

Agent Vault stores `master.json` beside the vault. It contains a verifier, a wrapped random vault key, and recovery-code metadata, not the raw master key.

`s init` prints recovery codes once. Store them separately. If the master key and all recovery codes are lost, the vault cannot be recovered.

## Vault Location

Set the vault path explicitly:

```bash
export S_VAULT_PATH=/path/to/vault.senv
```

If omitted, Agent Vault uses `./.senv` when present, otherwise `~/.config/agent-vault/vault.senv`.

## Password

For non-interactive local testing only:

```bash
export S_KEY=test-password
```

For real use, prefer an interactive prompt or a password command through `S_KEY=!command`. Do not put real passwords directly into shell history.

Legacy key-file vaults can be migrated:

```bash
s migrate-key
```

Recovery commands:

```bash
s recovery rotate --auth
s recovery use
```

## Core Flow

```bash
s version
s init
s password change --auth
printf 'fake-value' | s add TEST_API_KEY --stdin --comment "Fake key" --tags api,test
s ls
s update TEST_API_KEY --comment "Updated comment"
s api ls
s backup --to ./backups
```

Default `s ls` output shows only the item name and comment. Use `s ls --json` when an agent needs structured safe metadata.

Human-only `run` injects the secret as an env var and redacts the value from stdout and stderr. Agents must use `s api request` instead.

## Agent Mode

```bash
S_AGENT_MODE=1 s ls
S_AGENT_MODE=1 s get TEST_API_KEY --auth
S_AGENT_MODE=1 s run TEST_API_KEY -- python3 script.py
```

The second and third commands must fail. Agent mode blocks raw reveal, raw secret injection, export, delete, purge, rollback, and restore-backup.

Agent API usage:

```bash
S_AGENT_MODE=1 s api ls
S_AGENT_MODE=1 s api request PROFILE --method GET --url https://api.example.com/path
```

Domain approval commands:

```bash
s api pending
s api pending --all
s api approve REQUEST_ID
s api reject REQUEST_ID
```

API profiles have an allowlist of approved hosts. If an API request uses a different host, Agent Vault blocks it and stores a pending approval. Approving the request adds that host to the profile. Rejecting it leaves the profile unchanged.

## Human-only Commands

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

Agents should use `archive` instead of delete.
