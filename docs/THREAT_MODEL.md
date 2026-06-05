# Agent Vault Threat Model

## Core Thesis

Agents may use API-backed capabilities, but agents must never receive, read, print, store, or pass around raw API credentials.

Agent Vault is responsible for holding credentials and performing authenticated API calls on behalf of agents. The agent gets API results, not API keys.

## What This Protects Against

- Accidental key disclosure in agent chat, logs, shell output, command args, or generated files.
- Raw credentials leaking through subprocess environments.
- Agents discovering secret values through vault reveal, export, or backup paths.
- Agents using arbitrary shell programs as a path to capture API keys.

## What This Does Not Protect Against

- A fully compromised host.
- A human with the master key intentionally exporting secrets.
- A malicious or compromised Agent Vault implementation.
- Abuse of an API action that Agent Vault is explicitly asked to perform.

Agent Vault protects the credential. It does not decide whether a requested business action is wise.

## Current Policy

In agent mode:

- `s ls` and `s api ls` may show safe metadata.
- `s api request` may perform approved-profile API requests.
- `s get`, `s export`, delete, purge, rollback, recovery, and password commands are blocked.
- `s run KEY -- command` is blocked because it gives the subprocess a raw secret.
- `s cmd run COMMAND` is blocked when the stored command uses any secret.

## Secure API Execution

Agents should use:

```bash
S_AGENT_MODE=1 s api request PROFILE --method GET --url https://api.example.com/path
```

Agent Vault loads the profile, verifies the request host is allowed, injects authentication internally, performs the request, redacts output, and records an audit entry.

## Documentation Rule

Any future Agent Vault feature must be checked against the core thesis. If it gives an agent a raw credential, places a credential in an agent-controlled subprocess environment, or lets an agent bypass Agent Vault's API execution layer, it violates the project requirement.
