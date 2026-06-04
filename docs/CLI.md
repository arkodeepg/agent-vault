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

The default master key is `password`. Please change it for fuck's sake. Use `s password change --auth` for CLI rotation or the `Master key` tab in the dashboard. Docker should use `S_KEY_FILE=/data/master.key` so the dashboard can persist the update.

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

## Core Flow

```bash
s init
printf 'fake-value' | s add TEST_API_KEY --stdin --comment "Fake key" --tags api,test
s ls
s update TEST_API_KEY --comment "Updated comment"
s run TEST_API_KEY -- python3 -c 'import os; print(os.environ["TEST_API_KEY"])'
s backup --to ./backups
```

`run` injects the secret as an env var and redacts the value from stdout and stderr.

## Agent Mode

```bash
S_AGENT_MODE=1 s ls
S_AGENT_MODE=1 s get TEST_API_KEY --auth
```

The second command must fail. Agent mode blocks raw reveal, export, delete, purge, rollback, and restore-backup.

## Human-only Commands

These require an interactive terminal and `--auth`:

```bash
s get NAME --auth
s export --auth
s delete NAME --auth
s purge NAME --auth
s rollback NAME --to 1 --auth
s restore-backup FILE --auth
```

Agents should use `archive` instead of delete.
