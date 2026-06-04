# Security Model

Agent Vault is designed for one-person internal use on a trusted machine or private Tailscale network. It is not a multi-user password manager.

## Storage

Vault state is split across two files:

```text
vault.senv      encrypted secret values, command values, and history
master.json     password verifier, wrapped vault key, and recovery-code metadata
```

The raw master key is not stored. The entered master key is checked against a slow scrypt verifier, then used to unwrap a random vault encryption key. That vault key decrypts `vault.senv`.

Changing the master key rewraps the vault key. It does not need to decrypt and rewrite every stored secret.

## Recovery

First setup, migration, and `s recovery rotate --auth` print recovery codes once.

Each recovery code can reset the master key one time. Used codes are removed from `master.json`.

Store recovery codes away from:

- `vault.senv`
- `master.json`
- normal vault backups
- chat logs and agent context

If the master key and all recovery codes are lost, the vault is intentionally unrecoverable.

## Agent Boundaries

Agents can list safe metadata and run commands with injected secrets. They should not receive raw secret values.

Blocked in agent mode:

```bash
s get
s export
s delete
s purge
s rollback
s restore-backup
s password change
s recovery rotate
s recovery use
```

Agents should archive instead of deleting.

## Web UI

The dashboard requires the master key before reading metadata or mutating vault state. The key is kept in browser session storage for the current browser session.

The web server sends:

- `Cache-Control: no-store`
- restrictive content security policy
- frame, MIME sniffing, referrer, and permissions-policy headers

The web UI does not expose raw reveal, purge, rollback, or restore-backup.

## Network Exposure

Default web binding is localhost. For home-server access, expose it only through Tailscale or another private authenticated layer.

Do not publish the service directly to the public internet. There is no multi-user auth, rate limiting, account lockout, or audit-grade session management.

## Backups

Back up `vault.senv` and `master.json` together. Do not place recovery codes inside the same backup folder.

Encrypted backup files are safe to copy, but if an attacker gets both the backup and the master key or a recovery code, they can recover the vault.

## Remaining Risks

- A compromised host can read secrets when commands are run.
- A malicious browser extension can access dashboard session storage.
- A command run through `s run` receives real secrets in its subprocess environment.
- Safe metadata is not encrypted separately from normal vault access. Names, comments, tags, timestamps, and last-three-character hints are intentionally visible through list APIs after unlock.
- This is single-user tooling, not a replacement for Bitwarden, 1Password, Vaultwarden, or HashiCorp Vault when shared access, policy controls, or external audit requirements matter.
