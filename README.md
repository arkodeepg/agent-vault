# s — encrypted env store

Your agent doesn't need to see your secrets. `s` encrypts secrets with age + SSH keys, injects them into subprocesses at runtime, and scrubs them from output. The agent orchestrates; `s` handles the secrets.

```bash
# Agent writes this:
s -- curl -H "Authorization: Bearer $API_KEY" https://api.example.com

# Agent sees: ✅ response (secret replaced with ***)
# What ran: curl with the real key injected
```

## Setup

```bash
s init                          # creates .senv, registers your SSH key
s set API_KEY                   # interactive (hidden input)
s set DB_URL=postgres://...     # inline
```

## Managing secrets

```bash
s set KEY=VALUE                 # add/update (inline)
s set KEY                       # add/update (interactive, hidden)
s set KEY --stdin               # add/update (piped)
s get KEY                       # show decrypted value
s rm KEY                        # delete
s list                          # list names
```

## Import / Export

```bash
s import .env                   # import from .env file
s import --stdin                # import KEY=VALUE lines from stdin
s import --from-env API_KEY     # import $API_KEY from current env
s export                        # export all as KEY=VALUE to stdout
s export --file .env            # export to file
```

## Scanning for leaks

```bash
s scan                          # scan all git-tracked files
s scan --staged                 # scan only staged files (pre-commit hook)
s scan --path ./src             # scan specific directory
```

Checks your actual secret values against file contents — no regex false positives.

## Running commands

```bash
s -- curl -H "Authorization: Bearer $API_KEY" https://api.example.com
s -- docker compose up
s -- env | grep API              # shows *** instead of real values
```

Secrets are injected as env vars. Output (stdout + stderr) is scrubbed in real-time — any secret value is replaced with `***`.

## Session tickets

```bash
s unlock                        # decrypt once, cache for 7 days
s lock                          # destroy cached session
s status                        # show store info + session state
```

The ticket is encrypted with a key derived from boot_id + store path + host list. It auto-expires on reboot, host changes, or after 7 days.

## Multi-host

```bash
s hosts                         # list authorized hosts
s hosts add server ~/.ssh/server.pub
s hosts remove old-laptop
```

Secrets are encrypted to all hosts. Adding secrets only needs public keys (no private key required). Adding/removing hosts re-wraps all values.

## How it works

- Each secret is independently age-encrypted to all SSH ed25519 recipients
- `.senv` is a YAML file safe to commit (only encrypted blobs)
- Session tickets use ChaCha20-Poly1305 keyed from boot_id via HKDF
- Output scrubbing uses byte-literal matching with a sliding buffer
- No daemon, no network, no keychain dependency — just your SSH key

## Install

```bash
cargo install --path .
```

## Environment variables

| Variable | Purpose |
|---|---|
| `S_IDENTITY` | Path to SSH private key (default: `~/.ssh/id_ed25519`) |
| `S_TICKET_DIR` | Override ticket cache location |
