# Agent Vault Plan

Date: 2026-06-04
Base project: `tobi/s`
Project path: `/mnt/DATA/projects/agent-vault`

## Goal

Build a single-user internal secret and command vault for AI-assisted workflows.

The vault must let agents discover, add, update, and use secrets without seeing raw API keys, passwords, env values, or exported secret data. Humans must be present for destructive operations and raw reveal operations.

The product must work in three modes:

1. CLI-only mode, installed as a local binary.
2. Docker/server mode, with a private web UI and API.
3. Hybrid mode, where CLI and Docker use the same encrypted vault safely.

## Starting Point

The cloned `tobi/s` project already provides:

- Encrypted `.senv` storage.
- Secret injection into subprocesses as env vars.
- Output redaction for injected secrets.
- Safe non-TTY blocking for raw `get` and `export`.
- Git leak scanning against actual stored secret values.
- Simple history and rollback.

It does not yet provide:

- Item comments.
- Typed entries.
- Command registry.
- Soft archive instead of permanent delete.
- Agent policy mode.
- Master action password for reveal and destructive operations.
- Docker/web frontend.
- File locking for hybrid access.
- Argon2id password hardening.
- Test coverage.

## Product Rules

### One-person internal use

No multi-user team system in v1. Avoid roles, sharing, organizations, or external auth providers.

### Agent-safe by default

Agents can:

- List safe metadata.
- Add entries.
- Update values and metadata.
- Archive entries.
- Restore entries.
- Run commands with secrets injected and redacted.
- Scan for leaks.

Agents cannot:

- Read raw values.
- Export raw values.
- Permanently delete entries.
- Purge history.
- Roll back values without human confirmation.

### Human-required actions

These require a real interactive terminal or equivalent frontend human confirmation:

- `s get <NAME> --auth`
- `s export --auth`
- `s delete <NAME> --auth`
- `s purge <NAME> --auth`
- `s rollback <NAME> --to <VERSION> --auth`

Do not support passing the master password as a visible command argument. Visible password args can leak through shell history, process lists, logs, terminal recordings, or agent transcripts.

### Two password concepts

Vault encryption password:

- Used internally to decrypt/encrypt stored values.
- Needed for operations that use or change encrypted values.
- Can come from TTY prompt, env command, Docker secret, or frontend unlock.

Master action password:

- Used to authorize reveal and destructive operations.
- Required for raw reads, export, permanent delete, purge, and rollback.
- Must not be written in command text.

For v1, the master action password can be the same secret entered through a separate confirmation prompt, but the design should keep the API separate so it can become a separate password later.

## Data Model

Replace the current key-only model with typed vault items.

```yaml
version: 2
items:
  OPENROUTER_API_KEY:
    type: secret
    value: "<encrypted blob>"
    comment: "Used for OpenRouter model calls from local agents."
    tags: ["api", "ai"]
    archived: false
    created_at: "2026-06-04T00:00:00Z"
    updated_at: "2026-06-04T00:00:00Z"
    history: []

  SMARTLEAD_EXPORT:
    type: command
    value: "<encrypted or encoded command template>"
    comment: "Exports Smartlead campaign metrics."
    tags: ["smartlead", "reporting"]
    uses: ["SMARTLEAD_API_KEY"]
    archived: false
    created_at: "2026-06-04T00:00:00Z"
    updated_at: "2026-06-04T00:00:00Z"
```

Item types:

- `secret`: API key, password, token, env value.
- `command`: stored command template with optional required secrets.
- `note`: non-secret operational note. Useful for agent context. The note body still follows the comment limit.

Comment rule:

- Limit comments to 180 words.
- Comments are visible to agents through `s ls`.
- Comments must never include raw secrets.

Backward compatibility:

- Existing `.senv` files using `keys:` must continue to load.
- First write can migrate to `version: 2`.

## Command Design

### General

```bash
s init
s status
s doctor
```

`s init` creates a vault.

`s status` prints safe status only: vault path, item counts, archive counts, lock status, binary version.

`s doctor` checks file permissions, parseability, encryption version, Docker volume warnings, and git hook status.

### Safe listing

```bash
s ls
s ls --json
s ls --all
s ls --type secret
s ls --tag ai
```

Default output includes:

- name
- type
- comment
- tags
- required secrets for commands
- updated date

Default output excludes:

- raw value
- encrypted blob
- archived items, unless `--all` is provided

### Add

```bash
s add <NAME>
s add <NAME> --stdin
s add <NAME> --type secret --comment "..."
s add <NAME> --type note --comment "..."
```

Rules:

- Default type is `secret`.
- Interactive add reads masked value from TTY.
- `--stdin` reads value without echoing it.
- Adding an existing active name fails and suggests `s update`.

### Update

```bash
s update <NAME>
s update <NAME> --stdin
s update <NAME> --comment "..."
s update <NAME> --name <NEW_NAME>
s update <NAME> --tags api,shopify
s update <NAME> --type secret
```

Rules:

- Agents may update values and metadata.
- Values are never echoed.
- Renaming preserves history and audit trail.
- Updating a value stores previous value in history.

### Raw reveal

```bash
s get <NAME> --auth
```

Rules:

- Human-only.
- Requires TTY or frontend human confirmation.
- Requires master action password.
- Refuses in agent mode.

### Run

```bash
s run <NAME> [NAME...] -- <command>
s <NAME> [NAME...] -- <command>
```

Rules:

- Injects named secrets as env vars.
- Redacts secret values from stdout and stderr.
- Does not reveal raw values to agents.
- Works with Python, Node, shell scripts, curl, and project venvs.

Python example:

```bash
s run OPENAI_API_KEY -- venv/bin/python execution/example.py
```

Python reads:

```python
import os
api_key = os.environ["OPENAI_API_KEY"]
```

### Command registry

```bash
s cmd ls
s cmd add <COMMAND_NAME> --uses API_KEY --comment "..." -- <command>
s cmd update <COMMAND_NAME> --comment "..."
s cmd update <COMMAND_NAME> --uses API_KEY,DB_URL
s cmd run <COMMAND_NAME>
s cmd archive <COMMAND_NAME>
s cmd restore <COMMAND_NAME>
s cmd delete <COMMAND_NAME> --auth
```

Rules:

- Command entries are discoverable through `s ls` and `s cmd ls`.
- `s cmd run` injects declared secrets.
- Output is redacted.
- Command deletion is master-protected.

### Archive and restore

```bash
s archive <NAME>
s restore <NAME>
```

Rules:

- Agent-safe.
- Reversible.
- Archived entries are hidden from normal `s ls`.
- Archived entries cannot be used by `s run` unless explicitly restored.

### Permanent delete

```bash
s delete <NAME> --auth
s purge <NAME> --auth
```

Rules:

- Human-only.
- Requires TTY or frontend human confirmation.
- Requires master action password.
- Requires typing the item name to confirm.
- `delete` removes the active item but can preserve audit metadata.
- `purge` removes item and history.
- Refuses in agent mode.

### History and rollback

```bash
s history <NAME>
s rollback <NAME> --to <VERSION> --auth
```

Rules:

- History display is safe and value-free.
- Rollback is master-protected because it changes a live secret value.

### Import and export

```bash
s import .env
s import --stdin
s export --auth
s export --file .env --auth
```

Rules:

- Import can be agent-safe if values enter through stdin and are not echoed.
- Export is human-only.
- Export refuses in agent mode.

### Scan and audit

```bash
s scan
s scan --staged
s audit
s audit --json
```

Rules:

- `scan` checks files for actual stored secret values.
- `audit` lists safe event metadata: action, item name, actor mode, timestamp.
- Audit never stores or prints raw values.

## Agent Mode

Use an explicit environment variable:

```bash
S_AGENT_MODE=1
```

When enabled:

Allowed:

- `s ls`
- `s add`
- `s update`
- `s archive`
- `s restore`
- `s run`
- `s cmd ls`
- `s cmd add`
- `s cmd update`
- `s cmd run`
- `s scan`
- `s status`
- `s doctor`
- `s audit`

Blocked:

- `s get`
- `s export`
- `s delete`
- `s purge`
- `s rollback`

The blocked commands must fail even if the agent supplies flags incorrectly.

## Docker and Server Mode

### Docker goals

- Run locally or on private home server.
- Use mounted encrypted vault volume.
- Support CLI inside container.
- Support private web UI.
- Support agent-safe API endpoints.

### Docker services

```yaml
services:
  vault-api:
    build: .
    volumes:
      - ./data:/data
    environment:
      VAULT_PATH: /data/vault.senv

  vault-web:
    build: ./web
    depends_on:
      - vault-api
```

### API categories

Agent-safe endpoints:

- `GET /items`
- `POST /items`
- `PATCH /items/:name`
- `POST /items/:name/archive`
- `POST /items/:name/restore`
- `POST /commands/:name/run`
- `GET /audit`

Human-only endpoints:

- `POST /items/:name/reveal`
- `POST /items/:name/delete`
- `POST /items/:name/purge`
- `POST /items/:name/rollback`
- `POST /export`

### Web UI

Core screens:

- Vault list.
- Add item.
- Edit metadata.
- Edit value.
- Command registry.
- Audit log.
- Human confirmation dialog for reveal/delete/purge/rollback.

The UI must hide values by default and require explicit human confirmation for reveal.

## Hybrid Access and Locking

The CLI and server may share the same vault file.

Required:

- File lock before write.
- Atomic save.
- Detect external modification.
- Refuse write if stale state would overwrite newer data.

Implementation options:

- Start with OS file lock using a lockfile.
- Keep atomic temp-file rename.
- Add reload-before-write.

## Security Changes

### Replace password derivation

Current base project uses HKDF directly from password and salt. Replace with Argon2id for human password resistance.

Target:

- Argon2id
- Per-value random salt
- Store KDF metadata with encrypted blob
- Keep old format readable for migration

### Redaction

Keep byte-level output redaction.

Add tests for:

- secret printed in stdout
- secret printed in stderr
- secret split across chunks
- multiple secrets

### Secrets in process args

Do not encourage secrets in command arguments. Prefer env injection. Document that CLI cannot fully protect secrets passed directly to subprocess args by the user.

## Testing Strategy

Every phase must include a verification command before commit.

Minimum test types:

- Rust unit tests for store parsing and encryption.
- CLI integration tests using temp directories.
- Redaction tests using random fake API keys.
- Agent mode deny tests.
- Human-only command tests for non-TTY refusal.
- Docker smoke test when Docker files exist.

Use random fake values only, for example:

```text
test_sk_1234567890abcdef_FAKE_ONLY
```

Never use real API keys in tests.

## Phase Plan and Commit Gates

### Phase 0: Baseline and project setup

Tasks:

1. Clone `tobi/s` into `/mnt/DATA/projects/agent-vault`.
2. Add this planning document.
3. Run baseline build and tests if possible.
4. Commit: `chore: add agent vault implementation plan`

Verification:

```bash
cargo test
cargo build
```

### Phase 1: Rename and baseline safety

Tasks:

1. Rename package metadata to `agent-vault` while keeping binary name `s` initially.
2. Update README to mark this as internal single-user agent vault.
3. Add basic test harness.
4. Add CI-ready test command documentation.

Verification:

```bash
cargo test
cargo build
```

Commit:

```text
chore: establish agent vault baseline
```

### Phase 2: Versioned storage and metadata

Tasks:

1. Introduce `version: 2` storage.
2. Add `VaultItem` with type, value, comment, tags, archived, timestamps, history, uses.
3. Keep backward compatibility with existing `keys:` files.
4. Add 180-word comment validation.
5. Add safe JSON serialization for list output.

Verification:

```bash
cargo test
cargo build
```

Commit:

```text
feat: add typed vault metadata
```

### Phase 3: Command surface for list, add, update, archive, restore

Tasks:

1. Add `s ls` with metadata and `--json`.
2. Add `s add`.
3. Add `s update`.
4. Replace direct `rm` behavior with `archive`.
5. Add `restore`.
6. Keep aliases only where safe.

Verification:

```bash
cargo test
cargo build
```

Manual smoke:

```bash
S_KEY=test-password cargo run -- init
printf 'test_sk_1234567890abcdef_FAKE_ONLY' | S_KEY=test-password cargo run -- add TEST_API_KEY --stdin --comment "Fake key for redaction tests."
S_KEY=test-password cargo run -- ls
S_KEY=test-password cargo run -- update TEST_API_KEY --comment "Updated fake API key for testing."
S_KEY=test-password cargo run -- archive TEST_API_KEY
S_KEY=test-password cargo run -- restore TEST_API_KEY
```

Commit:

```text
feat: add safe item management commands
```

### Phase 4: Agent mode policy

Tasks:

1. Add `S_AGENT_MODE=1` detection.
2. Block raw reveal, export, delete, purge, rollback.
3. Add deny tests.
4. Add clear error messages.

Verification:

```bash
cargo test
cargo build
```

Manual smoke:

```bash
S_AGENT_MODE=1 S_KEY=test-password cargo run -- ls
S_AGENT_MODE=1 S_KEY=test-password cargo run -- get TEST_API_KEY --auth
```

Commit:

```text
feat: enforce agent mode safety policy
```

### Phase 5: Master-protected reveal and destructive operations

Tasks:

1. Add `--auth` requirement for `get`, `export`, `delete`, `purge`, `rollback`.
2. Add TTY-only prompt for master action password.
3. Add typed-name confirmation for permanent delete and purge.
4. Ensure non-TTY refusal works.
5. Add tests for non-TTY refusal.

Verification:

```bash
cargo test
cargo build
```

Commit:

```text
feat: protect reveal and destructive operations
```

### Phase 6: Command registry

Tasks:

1. Add command item support.
2. Add `s cmd ls`.
3. Add `s cmd add`.
4. Add `s cmd update`.
5. Add `s cmd run`.
6. Inject declared secrets and redact outputs.
7. Block archived command runs.

Verification:

```bash
cargo test
cargo build
```

Manual smoke:

```bash
S_KEY=test-password cargo run -- cmd add PRINT_FAKE --uses TEST_API_KEY --comment "Prints fake key to confirm redaction." -- sh -c 'echo $TEST_API_KEY'
S_KEY=test-password cargo run -- cmd run PRINT_FAKE
```

Expected output:

```text
[REDACTED]
```

Commit:

```text
feat: add command registry
```

### Phase 7: Argon2id encryption hardening

Tasks:

1. Add Argon2id dependency.
2. Add versioned encrypted blob format.
3. Keep old format decryptable.
4. Re-encrypt old values on update.
5. Add tests for new and old blob compatibility.

Verification:

```bash
cargo test
cargo build
```

Commit:

```text
feat: harden password derivation with argon2id
```

### Phase 8: File locking and hybrid safety

Tasks:

1. Add write lock.
2. Add reload-before-write.
3. Keep atomic save.
4. Add stale write protection.
5. Add tests for concurrent write behavior where possible.

Verification:

```bash
cargo test
cargo build
```

Commit:

```text
feat: add vault file locking
```

### Phase 9: Docker CLI mode

Tasks:

1. Add Dockerfile for CLI.
2. Add docker-compose CLI example.
3. Mount vault volume.
4. Document `docker exec vault s ls`.

Verification:

```bash
docker build -t agent-vault:local .
docker run --rm agent-vault:local s help
```

Commit:

```text
feat: add dockerized cli
```

### Phase 10: API and frontend

Tasks:

1. Add private API server.
2. Add web UI.
3. Add frontend screens for list, add, update, command registry, audit.
4. Add human confirmation flows for reveal/delete/purge/rollback.
5. Add Docker Compose for API and web.

Verification:

```bash
cargo test
cargo build
docker compose up --build
```

Manual browser checks:

- Add fake key.
- Confirm it appears in list.
- Update comment.
- Add command.
- Run command and confirm redaction.
- Confirm reveal requires human auth.

Commit:

```text
feat: add private web interface
```

### Phase 11: GitHub integration

Tasks:

1. Create GitHub repository after local implementation is stable.
2. Add remote.
3. Add GitHub Actions for build and tests.
4. Push main branch.
5. Tag first usable release.

Verification:

```bash
git status
git remote -v
git log --oneline -5
```

Commit:

```text
ci: add github test workflow
```

## Definition of Done for v1

The first usable version is done when:

- CLI can init, add, update, list, archive, restore, run, scan.
- `s ls` gives useful agent-safe metadata.
- Agents cannot get raw values in `S_AGENT_MODE=1`.
- Human-only actions require TTY/auth.
- Fake API key redaction is verified.
- Command registry can run Python or shell commands with injected secrets.
- Docker CLI mode works.
- Tests pass before each commit.
- GitHub remote exists with test workflow.

## Open Decisions

No blocking questions remain.

Later decisions:

- Whether master action password should be separate from vault password in v1 or v2.
- Whether command templates should be encrypted or only stored as metadata.
- Whether frontend should be Rust-rendered, React, or simple static HTML plus API.

Current recommendation:

- Use same human-entered password path for v1 but keep the code abstraction separate.
- Encrypt command templates if they may contain sensitive paths or operational details.
- Start frontend simple after CLI is stable.


## 2026-06-04 Addendum: Storage, Backup, Help, and Runtime

### Where data is stored

The default source of truth is one encrypted vault file on disk, not a hosted database.

Recommended paths:

```text
CLI local:       ~/.config/agent-vault/vault.senv
Project local:   ./.senv
Docker server:   /data/vault.senv
```

The path can be overridden for both CLI and Docker:

```bash
S_VAULT_PATH=/mnt/DATA/projects/agent-vault-data/vault.senv s ls
```

Docker should mount the encrypted vault as a volume:

```yaml
volumes:
  - ./data:/data
environment:
  S_VAULT_PATH: /data/vault.senv
```

Stored in encrypted or safe form:

- Secret values, encrypted.
- Command templates, encrypted if they may contain sensitive operational details.
- Value history, encrypted.
- Safe metadata: name, type, comment, tags, archived flag, timestamps, required secret names.
- Audit metadata: action, item name, timestamp, mode, result.

Never stored in plaintext:

- API key values.
- Password values.
- Env values.
- Exported raw secrets.
- Master action password.

Do not use Postgres or SQLite as the primary v1 store. A single encrypted vault file is easier to back up, move between CLI and Docker, and protect for a one-person home-server setup.

### Language decision

Keep the core CLI and vault engine in Rust unless a real blocker appears.

Reasons:

- Rust gives a single portable binary for local machines and the home server.
- The core job is security-sensitive process handling, env injection, redaction, and file locking.
- The cloned `tobi/s` code is already small and close to the required behavior.
- Docker can package the same binary for server mode.

The web layer can be revisited later, but the core vault behavior should live in one shared engine so CLI, Docker, and API behavior cannot drift.

Current recommendation:

- Core CLI and vault engine: Rust.
- API server: Rust, using the same vault library.
- Frontend: simple private web UI after CLI is stable.
- Tests: Rust unit and integration tests, plus Docker smoke tests.

### Required help command

`s help` and `s help <command>` must exist.

Examples:

```bash
s help
s help ls
s help add
s help cmd
```

This is required so humans and agents can safely discover the available command surface without guessing.

### Backup and restore

Backups are required because permanent delete exists for humans.

Commands:

```bash
s backup
s backup --to /path/to/backups
s backup --include-archived
s restore-backup <BACKUP_FILE> --auth
```

Backup format:

```text
agent-vault-backup-YYYYMMDD-HHMMSS.tar.zst
```

Backup contents:

- encrypted vault file
- safe audit log
- manifest with app version, created date, vault path, item count
- checksum file

Backup rules:

- Backup must not decrypt secrets.
- Backup is safe to copy to normal backup storage because values remain encrypted.
- Restore is human-only and requires `--auth`.
- Restore writes to a new file by default.
- Replacing the active vault requires explicit human confirmation.

Suggested home-server backup path, configurable and not hardcoded:

```text
/mnt/DATA/backups/agent-vault/
```

### Network and open-port security

Default server behavior:

- Bind API to `127.0.0.1` by default.
- Require explicit config to bind to LAN.
- Print a warning if bound to `0.0.0.0`.
- No default public exposure.
- No unauthenticated reveal, export, delete, purge, rollback, or restore endpoints.
- No raw secret values in logs.
- No request body logging for endpoints that may carry values.

Home-server deployment should use one of:

- localhost only plus SSH tunnel
- Tailscale-only binding
- reverse proxy with local auth, only if intentionally configured

Open port checks must be part of `s doctor` and Docker smoke testing.

### Updated phase requirements

Phase 0 also includes README rewrite with credit to the original inspiration: https://github.com/tobi/s

Phase 3 must add `s help` and `s help <command>` alongside `s ls`, `s add`, `s update`, `s archive`, and `s restore`.

Add Phase 3b for backups:

1. Add `s backup`.
2. Add backup manifest and checksum.
3. Add human-only `s restore-backup <FILE> --auth`.
4. Ensure backup never decrypts values.
5. Add tests for backup manifest and safe restore behavior.
6. Commit only after tests pass.

Docker and server phases must bind to localhost by default and include an unsafe binding check.
