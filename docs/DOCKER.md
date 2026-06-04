# Docker Usage

Docker mode packages the same `s` CLI and stores the encrypted vault at `/data/vault.senv`.

CLI Docker mode exposes no ports. The future web UI must bind to `127.0.0.1` by default.

## Default master key

The default master key is `password`. Please change it for fuck's sake. Use `s password change --auth` for CLI rotation or the `Master key` tab in the dashboard. Docker should use `S_KEY_FILE=/data/master.key` so the dashboard can persist the update.

## Build

```bash
docker build -t agent-vault:local .
```

The build is offline-friendly because required Python crypto packages are vendored under `docker/vendor`.

## Help

```bash
docker run --rm agent-vault:local help
```

## Disposable Test Vault

```bash
mkdir -p data
docker run --rm -v "$PWD/data:/data" -e S_KEY_FILE=/data/master.key agent-vault:local init
printf 'test_sk_1234567890abcdef_FAKE_ONLY' | docker run --rm -i -v "$PWD/data:/data" -e S_KEY_FILE=/data/master.key agent-vault:local add TEST_API_KEY --stdin --comment "Fake key"
docker run --rm -v "$PWD/data:/data" -e S_KEY_FILE=/data/master.key agent-vault:local ls
docker run --rm -v "$PWD/data:/data" -e S_KEY_FILE=/data/master.key agent-vault:local run TEST_API_KEY -- python -c "import os; print(os.environ['TEST_API_KEY'])"
```

Expected command output:

```text
[REDACTED]
```

## Agent Mode

```bash
docker run --rm -v "$PWD/data:/data" -e S_AGENT_MODE=1 -e S_KEY_FILE=/data/master.key agent-vault:local ls
```

Agent mode blocks raw reveal and destructive operations.

## Web UI

The web UI is dark mode by default and is intended for Docker mode. It includes search and a Copy agent docs button.

```bash
docker compose up --build
```

Open:

```text
http://127.0.0.1:8787
```

The compose file maps only `127.0.0.1:8787`, so it is not exposed on the LAN by default.

The dashboard asks for the master key before loading metadata or allowing updates.
