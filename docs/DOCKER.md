# Docker Usage

Docker mode packages the `s` CLI, web dashboard, and encrypted vault storage.

## Build

```bash
docker build -t agent-vault:local .
```

The build is offline-friendly because required Python crypto packages are vendored under `docker/vendor`.

## Run Dashboard

```bash
docker compose up --build
```

Open:

```text
http://127.0.0.1:8787
```

Default master key: `password`. Change it immediately.

## Storage

```text
/data/vault.senv      encrypted vault data
/data/master.json     verifier, wrapped vault key, recovery-code metadata
```

Store recovery codes outside the mounted `/data` directory.

## CLI In Container

```bash
docker run --rm agent-vault:local help
docker run --rm agent-vault:local version
docker run --rm -v "$PWD/data:/data" agent-vault:local ls
```

Agent mode:

```bash
docker run --rm -v "$PWD/data:/data" -e S_AGENT_MODE=1 agent-vault:local ls
```

## Agent HTTP Token

Set:

```bash
S_AGENT_API_TOKEN=avagt_example
```

Agents send it as:

```text
x-agent-vault-token
```

This token allows brokered API requests only. It does not reveal raw credentials.

## Legacy Migration

Old Docker installs that used `/data/master.key` can migrate once:

```bash
docker compose run --rm agent-vault migrate-key
```

Save the printed recovery codes separately, then remove `S_KEY_FILE` from compose.
