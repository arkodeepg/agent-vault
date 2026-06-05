# Agent Vault

Agent Vault is a local password manager and API broker for AI agents.

Core rule:

```text
Agents may use API-backed capabilities, but agents must never receive, read, print, store, or pass around raw API credentials.
```

Agents see safe metadata and API responses. Agent Vault keeps the credentials, validates the destination, injects auth internally, and sends the request.

## How It Works

```mermaid
flowchart LR
    A[Agent or script] -->|profile, method, URL, body| B[Agent Vault]
    B --> C{Host approved?}
    C -->|No| D[Create pending domain request]
    C -->|Yes| E[Inject credential inside vault]
    E --> F[External API]
    F -->|response| B
    B -->|API result, no raw key| A
```

## Domain Approval

```mermaid
flowchart TD
    A[Script requests new host] --> B[Agent Vault blocks request]
    B --> C[Pending approval appears in dashboard]
    C --> D{User decision}
    D -->|Approve| E[Host added to profile allowlist]
    D -->|Reject| F[Profile unchanged]
    E --> G[Future requests to that host can run]
```

Path changes on an already approved host can be handled by scripts. Host changes need approval once.

## Quick Start

```bash
bin/s init
bin/s password change --auth
bin/s ls
```

Docker:

```bash
docker compose up --build
```

Open the dashboard:

```text
http://127.0.0.1:8787
```

The default master key is `password`. Change it immediately.

## Agent Usage

Agents should run with:

```bash
S_AGENT_MODE=1
```

Safe discovery:

```bash
S_AGENT_MODE=1 s ls
S_AGENT_MODE=1 s api ls
```

Safe API call:

```bash
S_AGENT_MODE=1 s api request BASECAMP \
  --method GET \
  --url https://3.basecampapi.com/example.json
```

Pending domains:

```bash
s api pending
s api approve REQUEST_ID
s api reject REQUEST_ID
```

## Storage

```text
vault.senv      encrypted vault data
master.json     verifier, wrapped vault key, recovery-code metadata
```

The raw master key is not stored. Recovery codes are printed once during setup or rotation. Store them separately from vault backups.

## Docs

- [Agent guide](docs/AGENT_README.md): what agents are allowed to do.
- [Security model](docs/SECURITY.md): boundaries, risks, and diagrams.
- [CLI usage](docs/CLI.md): command reference.
- [Web UI](docs/WEB.md): dashboard usage.
- [Docker usage](docs/DOCKER.md): container setup.
- [Threat model](docs/THREAT_MODEL.md): standing project requirement.

## Test

```bash
PYTHON=/mnt/DATA/AIW2/venv/bin/python scripts/smoke_cli.sh
```
