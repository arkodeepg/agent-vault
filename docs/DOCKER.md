# Docker Usage

Docker mode packages the same `s` CLI and stores vault state under `/data`.

CLI Docker mode exposes no ports. The web UI binds to `127.0.0.1` by default through compose.

## Default master key

The default master key is `password`. Change it immediately with `s password change --auth` or the `Master key` tab in the dashboard.

Docker stores:

```text
/data/vault.senv      encrypted vault data
/data/master.json     verifier, wrapped vault key, recovery-code metadata
```

`master.json` does not contain the raw master key. First setup prints recovery codes once. Store them outside the mounted `/data` directory.

## Build

```bash
docker build -t agent-vault:local .
```

The build is offline-friendly because required Python crypto packages are vendored under `docker/vendor`.

## Help

```bash
docker run --rm agent-vault:local help
docker run --rm agent-vault:local version
```

## Disposable Test Vault

```bash
mkdir -p data
docker run --rm -v "$PWD/data:/data" agent-vault:local init
printf 'test_sk_1234567890abcdef_FAKE_ONLY' | docker run --rm -i -v "$PWD/data:/data" agent-vault:local add TEST_API_KEY --stdin --comment "Fake key"
docker run --rm -v "$PWD/data:/data" agent-vault:local ls
docker run --rm -v "$PWD/data:/data" agent-vault:local run TEST_API_KEY -- python -c "import os; print(os.environ['TEST_API_KEY'])"
```

Expected command output:

```text
[REDACTED]
```

## Agent Mode

```bash
docker run --rm -v "$PWD/data:/data" -e S_AGENT_MODE=1 agent-vault:local ls
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

On first run, unlock with `password`, then change the master key immediately in the `Master key` tab.

## Migration

Old Docker installs that used `/data/master.key` can migrate once:

```bash
docker compose run --rm agent-vault migrate-key
```

Save the printed recovery codes separately, then remove `S_KEY_FILE` from compose.
