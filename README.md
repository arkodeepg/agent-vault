# Secret Exec (`s`)

Tiny encrypted env store with per-entry encryption, SSH-key-based multi-host
recipients, and a 7-day boot-clock-bound session.

```
s init [NAME]                 create ./.senv, add this host as a recipient
s add [-f] KEY=VALUE          add a variable (no identity required)
s import [-f] NAME            copy $NAME from the current env into the store
s list                        list variable names
s hosts                       list authorized hosts
s hosts add NAME <key|path>   authorize another host; re-wrap all values
s hosts remove NAME           revoke a host; re-wrap all values
s unlock                      start/refresh 7-day session (uses SSH identity)
s lock                        end session (delete ticket)
s status                      show store + hosts + session
s -- <cmd> [args...]          run cmd with vars in env, scrubbing echoes
```

Env overrides: `S_IDENTITY` (SSH private key path, default `~/.ssh/id_ed25519`)
and `S_TICKET_DIR` (session ticket location).

## The file

`.senv` is a small, inspectable YAML:

```yaml
hosts:
  laptop: "ssh-ed25519 AAAAC3Nz... tobi@laptop"
  agent:  "ssh-ed25519 AAAAC3Nz... agent@box"
keys:
  OPENAI_API_KEY: "YWdlLWVuY3J5cHRpb24ub3JnL3Yx..."
  DB_URL:         "YWdlLWVuY3J5cHRpb24ub3JnL3Yx..."
```

Each value under `keys` is an independent `age`-encrypted blob (base64'd),
wrapped to every recipient under `hosts`. Any host whose private key is on
the machine can decrypt.

## What needs an identity and what doesn't

| Operation | Needs SSH identity? | Why |
|---|---|---|
| `s init` | public only | reads `~/.ssh/id_*.pub` to seed `hosts` |
| `s add`, `s import` | **no** | just encrypts to the listed recipients |
| `s list`, `s status`, `s hosts` | no | YAML is readable |
| `s -- cmd`, `s unlock` | yes (or valid ticket) | decrypts values |
| `s hosts add/remove` | yes | must re-wrap every value for the new recipient set |

This breaks the skeleton-key problem of the old passphrase-based design:
a process/agent that can only *write* secrets no longer needs any crypto
material. Only the decrypt side carries a "skeleton", and even then it's an
SSH key file bound to physical possession of the machine, not a memorisable
string.

## Designed for AI coding agents

The primary use case is letting an AI agent run shell commands with your
secrets in their environment, **without ever seeing the secret values
themselves**.

```bash
# One-time setup
s init laptop
s add OPENAI_API_KEY=sk-proj-abc...xyz
s add STRIPE_SECRET=sk_live_...
s import GITHUB_TOKEN                 # pull from shell env if already loaded
s unlock                              # 7-day session begins

# The agent then runs shell commands through `s --`:
s -- curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
s -- psql "$DATABASE_URL" -c 'select count(*) from users'
s -- bash -c 'gh api /user --header "Authorization: token $GITHUB_TOKEN"'
```

The child receives real values in its environment. **The agent never does**:
if the command (or anything it spawns) echoes a secret on stdout/stderr, `s`
rewrites it to `***` before the agent sees it.

```
$ s -- bash -c 'echo "calling with $OPENAI_API_KEY"'
calling with ***
```

Consequences:

- Secrets don't enter the agent's context, transcripts, or logs.
- The 7-day ticket means the agent never needs your SSH key or passphrase.
- `s lock` instantly revokes the agent's ability to decrypt anything,
  without rotating the secrets themselves.
- `s hosts remove <agent-host>` permanently revokes from that box.

## 7-day session ticket (boot-clock-bound)

After an identity-authenticated operation, `s` writes a ticket at
`$XDG_CACHE_HOME/s/<sha256(abs(.senv))>.ticket` (Linux) or
`~/Library/Caches/s/…` (macOS). The ticket AEAD-encrypts the decrypted
entries map.

Ticket key:

```
TK = HKDF-SHA256(
  ikm  = boot_id,                  // /proc/sys/kernel/random/boot_id (Linux)
                                   // sysctl kern.boottime (macOS)
  salt = ticket.salt,              // fresh per ticket
  info = "s-ticket-v2|"
         || sha256(abs_store_path)
         || "|" || sha256(hosts-block)
         || "|" || uid
)
```

Expiry is stored as an absolute value of a monotonic boot-clock
(`CLOCK_BOOTTIME` on Linux, `CLOCK_MONOTONIC` on Darwin — both tick through
sleep on their respective OS). These clocks are kernel-sourced, count
through hibernate, and are not settable by userspace.

### What this enforces

| Event | What happens |
|---|---|
| Reboot | `boot_id` changes → TK differs → AEAD auth fails → ticket auto-deleted |
| 7 days elapsed | `boot_clock_now >= expiry` → rejected (kernel-authoritative) |
| Host added/removed | `hosts-block` hash changes → TK differs → ticket invalidated |
| Wall-clock jump (`date -s`, NTP) | irrelevant — we don't read wall clock |
| Suspend / hibernate used to "pause" | both clocks tick through sleep |
| Editing `expiry` in the ticket file | covered by AAD → auth fails |

### What it doesn't protect against

- **Same-uid attacker on this machine** while the ticket is valid: can read
  both the ticket and `boot_id`. Accepted cache cost.
- **Root**: owns everything anyway.
- **A compromised binary** you pass the env to via `s -- cmd`: still sees
  real values and can exfiltrate them. Scrubbing only covers *echo* back
  through the agent's own I/O channels.

## Output scrubbing

`s -- cmd` pipes the child's stdout/stderr through a byte-literal scrubber
that replaces occurrences of any stored value with `***`, using a sliding
tail buffer so secrets split across reads are still caught.

Caveats: the child doesn't see a TTY (pipes are used), and scrubbing is
literal — a program that re-encodes a secret (base64, JSON-escape,
URL-encode) before printing it will leak that encoding.

## Examples

Runnable scripts in `examples/`. Each uses its own `$S_TICKET_DIR` so they
don't touch your real session.

```
examples/01-basics.sh              init, add, list, exec, lock
examples/02-scrubbing.sh           scrubber behaviour + byte-by-byte test
examples/03-multi-host.sh          authorize + revoke a second host
examples/04-overwrite.sh           -f vs /dev/tty confirmation prompt
examples/05-import.sh              pulling values from the shell env
```

## Build / install

```
cargo build --release
./target/release/s help

# or via nix flake:
nix build .#s
nix profile add .#s
```

## File layout

```
src/
├── main.rs      CLI dispatch, commands, scrubbed child exec
├── store.rs     YAML load/save, per-entry age encrypt/decrypt
├── identity.rs  discover + load SSH private key (with passphrase prompt)
├── ticket.rs    session ticket cache, hosts-bound HKDF, boot-clock expiry
├── sysinfo.rs   per-OS: boot_id, boot_clock_ns, uid
└── scrub.rs     sliding-window secret scrubber for child I/O
```

Supported on Linux and macOS. SSH keys: ed25519 (rsa also works via age but
`init` currently picks `~/.ssh/id_ed25519` or `~/.ssh/hostkey`).
