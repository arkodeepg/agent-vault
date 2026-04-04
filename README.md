# Secret Exec (`s`)

Tiny encrypted env store with a 7-day, boot-clock-bound session.

`s` keeps a small, passphrase-encrypted `.senv` file next to your project
(think `.env`, but encrypted) and lets you run commands with those variables
in their environment. Re-echoes of the secret values on stdout/stderr are
scrubbed. After you enter the passphrase once, subsequent uses are
passphrase-free for **7 days of boot-clock time**, enforced by the kernel —
no wall-clock trust, no honor system.

## Designed for AI coding agents

The primary use case is letting an AI agent (Claude Code, Cursor, Aider, etc.)
call APIs on your behalf **without ever seeing the secret value itself**.

You unlock once:

```bash
s add OPENAI_API_KEY=sk-proj-abc123...xyz
s add STRIPE_SECRET=sk_live_...
# or pull from an existing shell env (e.g. the one you just `env`-loaded):
s import GITHUB_TOKEN
s unlock                  # enter passphrase; 7-day session begins
```

Then you let the agent run shell commands through `s --`:

```bash
s -- curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
s -- psql "$DATABASE_URL" -c 'select count(*) from users'
s -- bash -c 'gh api /user --header "Authorization: token $GITHUB_TOKEN"'
```

The child process receives the real values in its environment. **The agent
never does** — if the command (or anything it spawns) echoes the secret to
stdout/stderr, `s` rewrites it to `***` before the agent sees it:

```
$ s -- bash -c 'echo "calling with $OPENAI_API_KEY"'
calling with ***
```

This means:

- Secrets never enter the agent's context window, so they can't be leaked
  through a future prompt, a mis-behaved tool, or an exfiltration attempt.
- Secrets never land in agent transcripts / logs / screen recordings.
- The 7-day ticket means the agent doesn't need to know the passphrase
  either — it just runs `s -- ...` and it works, until the session expires.
- `s lock` instantly revokes the agent's ability to use any stored secret,
  without changing the secrets themselves.

Threat model caveat: the child process (curl, psql, etc.) still sees the real
value; a malicious tool the agent invokes can still exfiltrate. `s` protects
against leaks through the **agent's own I/O channels**, not against a
compromised binary you hand the env to.

Env overrides: `S_PASSPHRASE` (non-interactive passphrase), `S_TICKET_DIR`
(override ticket location, e.g. for per-project caches or tests).

```
s add [-f] KEY=VALUE  add to ./.senv (-f overwrites, else prompts if exists)
s import [-f] NAME    copy $NAME from the current env into the store
s list                list key names
s unlock              start/refresh a 7-day session (prompts passphrase)
s lock                end session (deletes the ticket)
s status              show session state
s -- <cmd> [args...]  run cmd with stored vars in env, scrubbing echoes
```

## How the encryption works

Two layers:

1. **Passphrase → data key (DK)** via Argon2id (64 MiB, t=3, p=1), wrapped
   with ChaCha20-Poly1305.
2. **DK → payload** (`KEY=VALUE\n` lines), again ChaCha20-Poly1305.

Binary layout of `.senv`:

```
magic "S1\0"          3 bytes
wdk_len (u32 LE)      4 bytes
wrapped_dk            81 bytes     <- "WDK1\0" + salt + nonce + AEAD(KEK, DK)
nonce                 12 bytes
ciphertext            len(payload) + 16
```

The payload's AEAD has the whole header (incl. `wrapped_dk`) as AAD, so the
ciphertext is cryptographically bound to the specific wrapped DK.

## How the 7-day session works

After a successful passphrase unlock, `s` writes a small **ticket** file at
`$XDG_CACHE_HOME/s/<sha256(abs(.senv))>.ticket` (Linux) or
`~/Library/Caches/s/…` (macOS).

The ticket stores an AEAD-encrypted copy of the DK. The ticket-encryption key
is derived from kernel-sourced inputs:

```
TK = HKDF-SHA256(
  ikm  = boot_id,                    // Linux: /proc/sys/kernel/random/boot_id
                                     // macOS: sysctl kern.boottime
  salt = ticket.salt,                // fresh per ticket
  info = "s-ticket-v1|"
         || sha256(abs_store_path)
         || "|" || sha256(wrapped_dk)
         || "|" || uid
)
```

Expiry is stored as an absolute value of a **monotonic boot-clock**:

- Linux: `clock_gettime(CLOCK_BOOTTIME)`
- macOS: `clock_gettime(CLOCK_MONOTONIC)` (on Darwin this one ticks through sleep)

Both clocks are kernel-sourced, monotonic, and not settable by userspace. They
tick through sleep/hibernate and reset at reboot.

### What this enforces

| Event | What happens |
|---|---|
| Reboot | `boot_id` rotates → TK unrecoverable → ticket's AEAD auth fails. Crypto-enforced. |
| 7 days elapsed | `boot_clock_now >= expiry` → ticket rejected. Kernel-sourced, unforgeable. |
| Suspend/hibernate used to "pause the clock" | Doesn't work — both clocks tick through sleep. |
| Wall-clock jump (`date -s`, NTP) | Irrelevant — we don't read the wall clock for expiry. |
| Editing the ticket file (expiry, nonce, …) | AAD includes all header fields → AEAD auth fails → rejected. |
| Store (`.senv`) stolen off the box | Passphrase still required. No DK ever leaves wrapped form outside this machine. |
| Ticket stolen off the box | Useless without that machine's current `boot_id`. |

### What this does NOT protect against

- **Same-uid attacker on this machine during the 7 days** — can read the
  ticket and your `boot_id`. Accepted cost of having a passphrase-less cache.
- **Root** — owns everything anyway.

## Output scrubbing

`s -- cmd` pipes stdout/stderr through a byte-literal scrubber that replaces
any occurrence of any stored secret with `***`, using a sliding tail buffer
so secrets split across reads are still caught.

Limitations:

- The child does not see a TTY (pipes are used). Programs that check
  `isatty()` will change behaviour — no color, line-buffered stdout.
- The scrubber is literal. If a program re-encodes the secret (base64, JSON
  escapes, URL-encoding) before printing it, that encoding will leak.
- stdin is inherited unchanged.

## Examples

See `examples/` for runnable scripts.

## Build

```
cargo build --release
./target/release/s help
```

Runtime deps: glibc. Supported on Linux and macOS.

## Files

```
src/
├── main.rs      CLI dispatch, commands, exec-with-scrub
├── store.rs     .senv v1 format: Argon2id-wrapped DK + ChaCha20Poly1305 payload
├── ticket.rs    session ticket: HKDF(boot_id), boot-clock expiry
├── sysinfo.rs   per-OS: boot_id, boot_clock_ns, uid
├── scrub.rs     sliding-window secret scrubber for child I/O
└── prompt.rs    rpassword wrapper + S_PASSPHRASE env override
```
