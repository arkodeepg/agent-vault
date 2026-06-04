# Web UI

The web UI is intended for Docker mode. It is dark mode by default and maps to localhost only through `docker-compose.yml`.

## Default master key

The default master key is `password`. Please change it for fuck's sake. Use `s password change --auth` for CLI rotation or the `Master key` tab in the dashboard. Docker should use `S_KEY_FILE=/data/master.key` so the dashboard can persist the update.

## Start

```bash
S_KEY='use-a-real-local-password-command-or-secret' docker compose up --build
```

Open:

```text
http://127.0.0.1:8787
```

## Features

- Unlock the dashboard with the current master key.
- Search by name, comment, type, tag, or dependency.
- Add secrets and notes.
- Update names, comments, tags, and values.
- Archive and restore items.
- Add and run stored commands.
- View activity metadata.
- Export active items as CSV after entering the master key. CSV output uses proper quoting for commas, quotes, and newlines.
- Copy agent documentation with the Copy agent docs button.

## Security Defaults

- Compose binds to `127.0.0.1:8787`, not the LAN.
- Metadata and mutation APIs require the dashboard unlock key.
- The web UI does not expose raw reveal, delete, purge, rollback, or restore-backup.
- CSV export is master-key gated and refuses to run in agent mode.
- Request bodies are not logged by default.
- Browser responses use `Cache-Control: no-store`.
- Vault data lives in the mounted `./data` directory as encrypted JSON.

Do not run this on `0.0.0.0` unless you intentionally put it behind trusted private networking such as Tailscale or an authenticated local reverse proxy.
