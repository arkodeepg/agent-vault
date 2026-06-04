# Web UI

The web UI is intended for Docker mode. It is dark mode by default and maps to localhost only through `docker-compose.yml`.

## Start

```bash
S_KEY='use-a-real-local-password-command-or-secret' docker compose up --build
```

Open:

```text
http://127.0.0.1:8787
```

## Features

- Search by name, comment, type, tag, or dependency.
- Add secrets and notes.
- Update names, comments, tags, and values.
- Archive and restore items.
- Add and run stored commands.
- View audit metadata.
- Copy agent documentation with the Copy agent docs button.

## Security Defaults

- Compose binds to `127.0.0.1:8787`, not the LAN.
- The web UI does not expose raw reveal, export, delete, purge, rollback, or restore-backup.
- Request bodies are not logged by default.
- Vault data lives in the mounted `./data` directory as encrypted JSON.

Do not run this on `0.0.0.0` unless you intentionally put it behind trusted private networking such as Tailscale or an authenticated local reverse proxy.
