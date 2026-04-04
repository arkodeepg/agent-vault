// s — append-only encrypted env store with a 7-day boot-time-bound session.
//
// Commands:
//   s add KEY=VALUE       append to ./.senv (append-only; no overwrites)
//   s list                list key names
//   s unlock              start/refresh 7-day session (prompts passphrase)
//   s lock                end session (delete ticket)
//   s status              show session + store state
//   s -- <cmd> [args...]  run cmd with vars in env, scrubbing echoes on stdout/stderr
//
// Every command that needs to decrypt the store first tries the session
// ticket. When the ticket is missing, expired, or invalidated by a reboot,
// we prompt for the passphrase exactly once and write a fresh ticket.
//
// See store.rs and ticket.rs for the crypto.

mod prompt;
mod scrub;
mod store;
mod sysinfo;
mod ticket;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};


const STORE_FILE: &str = ".senv";
const TICKET_LIFETIME_SECS: u64 = 7 * 24 * 60 * 60;

fn main() {
    if let Err(e) = run() {
        eprintln!("s: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        return Ok(());
    }
    if args[0] == "--" {
        args.remove(0);
        if args.is_empty() {
            bail!("missing command after --");
        }
        return cmd_exec(args);
    }
    match args[0].as_str() {
        "add" => {
            let (force, pos) = parse_force_and_positional(&args[1..], "s add [-f] KEY=VALUE")?;
            cmd_add(&pos, force)
        }
        "import" => {
            let (force, pos) = parse_force_and_positional(&args[1..], "s import [-f] NAME")?;
            cmd_import(&pos, force)
        }
        "list" | "ls" => cmd_list(),
        "unlock" => cmd_unlock(),
        "lock" => cmd_lock(),
        "status" => cmd_status(),
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        other => bail!("unknown command: {other} (try `s help`)"),
    }
}

fn print_usage() {
    eprintln!(
        "s — append-only encrypted env store with 7-day session\n\n\
         usage:\n  \
         s add [-f] KEY=VALUE  add a variable to ./{STORE_FILE}; -f overwrites\n  \
         s import [-f] NAME    copy $NAME from the current env into the store\n  \
         s list                list variable names stored\n  \
         s unlock              start/refresh session (prompts passphrase)\n  \
         s lock                end session (delete ticket)\n  \
         s status              show session state\n  \
         s -- <cmd> [args...]  run cmd with stored vars in env, scrubbing echoes\n\n\
         env:\n  \
         S_PASSPHRASE          non-interactive passphrase\n  \
         S_TICKET_DIR          override where session tickets are stored\n"
    );
}

fn store_path() -> PathBuf {
    PathBuf::from(STORE_FILE)
}

struct Unlocked {
    header: store::Header,
    dk: [u8; 32],
    entries: Vec<(String, String)>,
}

/// Open an existing store. Uses the ticket if valid, otherwise prompts and
/// writes a fresh ticket.
fn open_existing(path: &Path) -> Result<Unlocked> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if !store::is_v1(&raw) {
        bail!("{} is not in s v1 format (remove it and re-add your secrets)", path.display());
    }
    let header = store::parse_header(&raw)?;
    if let Some(dk) = ticket::try_load_dk(path, &header.wrapped_dk)? {
        let entries = store::decrypt_payload(&header, &dk)?;
        return Ok(Unlocked { header, dk, entries });
    }
    let pp = prompt::existing("unlock")?;
    let dk = store::unwrap_dk(&header.wrapped_dk, &pp)?;
    let entries = store::decrypt_payload(&header, &dk)?;
    ticket::save_dk(path, &header.wrapped_dk, &dk, Duration::from_secs(TICKET_LIFETIME_SECS))?;
    Ok(Unlocked { header, dk, entries })
}

fn parse_force_and_positional(args: &[String], usage: &'static str) -> Result<(bool, String)> {
    let mut force = false;
    let mut pos: Option<String> = None;
    for a in args {
        match a.as_str() {
            "-f" | "--force" => force = true,
            other if pos.is_none() => pos = Some(other.to_string()),
            _ => bail!("usage: {usage}"),
        }
    }
    Ok((force, pos.ok_or_else(|| anyhow!("usage: {usage}"))?))
}

fn cmd_import(name: &str, force: bool) -> Result<()> {
    if !store::valid_key(name) {
        bail!("invalid variable name: {name:?}");
    }
    let v = std::env::var(name)
        .with_context(|| format!("${name} is not set in the current environment"))?;
    let pair = format!("{name}={v}");
    cmd_add(&pair, force)
}

fn cmd_add(pair: &str, force: bool) -> Result<()> {
    let (k, v) = pair.split_once('=').ok_or_else(|| anyhow!("expected KEY=VALUE"))?;
    if !store::valid_key(k) {
        bail!("invalid key: {k:?}");
    }
    if v.contains('\n') {
        bail!("value must not contain newlines");
    }

    let path = store_path();
    if path.exists() {
        let u = open_existing(&path)?;
        let mut entries = u.entries;
        let existing = entries.iter().position(|(ek, _)| ek == k);
        let verb = if let Some(idx) = existing {
            if !force && !confirm_overwrite(k)? {
                bail!("aborted");
            }
            entries[idx].1 = v.to_string();
            "updated"
        } else {
            entries.push((k.to_string(), v.to_string()));
            "added"
        };
        store::write_store(&path, &u.header.wrapped_dk, &u.dk, &entries)?;
        eprintln!("s: {verb} {k}");
    } else {
        let pp = prompt::new()?;
        let dk = store::new_dk()?;
        let wrapped = store::wrap_dk(&pp, &dk)?;
        let entries = vec![(k.to_string(), v.to_string())];
        store::write_store(&path, &wrapped, &dk, &entries)?;
        ticket::save_dk(&path, &wrapped, &dk, Duration::from_secs(TICKET_LIFETIME_SECS))?;
        eprintln!("s: added {k}");
    }
    Ok(())
}

/// Ask the user to confirm an overwrite. Reads from /dev/tty so piped stdin
/// cannot silently answer "yes". Returns false when no TTY is available.
fn confirm_overwrite(key: &str) -> Result<bool> {
    use std::io::{BufRead, BufReader, Write};
    let tty = match std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(f) => f,
        Err(_) => {
            eprintln!("s: key {key} already exists and no TTY available; pass -f to overwrite");
            return Ok(false);
        }
    };
    let mut tty_w = tty.try_clone().context("cloning /dev/tty")?;
    write!(tty_w, "overwrite existing {key}? [y/N] ")?;
    tty_w.flush()?;
    let mut line = String::new();
    BufReader::new(tty).read_line(&mut line).context("reading from /dev/tty")?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}

fn cmd_list() -> Result<()> {
    let path = store_path();
    if !path.exists() {
        eprintln!("s: no {STORE_FILE} here");
        return Ok(());
    }
    let u = open_existing(&path)?;
    if u.entries.is_empty() {
        eprintln!("s: (empty)");
        return Ok(());
    }
    for (k, _) in &u.entries {
        println!("{k}");
    }
    Ok(())
}

fn cmd_unlock() -> Result<()> {
    let path = store_path();
    if !path.exists() {
        bail!("no {STORE_FILE} in current directory");
    }
    // Force a fresh ticket — "unlock" always means a new 7-day window.
    ticket::delete(&path)?;
    let u = open_existing(&path)?;
    let remaining = ticket::remaining_secs(&path, &u.header.wrapped_dk)?.unwrap_or(0);
    eprintln!(
        "s: unlocked ({} entries) — ticket valid for {}",
        u.entries.len(),
        fmt_duration(remaining)
    );
    Ok(())
}

fn cmd_lock() -> Result<()> {
    let path = store_path();
    ticket::delete(&path)?;
    eprintln!("s: locked");
    Ok(())
}

fn cmd_status() -> Result<()> {
    let path = store_path();
    if !path.exists() {
        println!("store:   none ({STORE_FILE} does not exist)");
        return Ok(());
    }
    let raw = std::fs::read(&path)?;
    if !store::is_v1(&raw) {
        println!("store:   not a v1 s store (unknown format)");
        return Ok(());
    }
    let header = store::parse_header(&raw)?;
    println!("store:   v1, {} bytes", raw.len());
    match ticket::remaining_secs(&path, &header.wrapped_dk)? {
        Some(secs) => println!("session: unlocked — {} remaining", fmt_duration(secs)),
        None => println!("session: locked"),
    }
    Ok(())
}

fn cmd_exec(args: Vec<String>) -> Result<()> {
    let path = store_path();
    if !path.exists() {
        bail!("no {STORE_FILE} here — run `s add KEY=VALUE` first");
    }
    let u = open_existing(&path)?;

    let mut cmd = Command::new(&args[0]);
    cmd.args(&args[1..]);
    for (k, v) in &u.entries {
        cmd.env(k, v);
    }

    let secrets: Vec<Vec<u8>> = u
        .entries
        .iter()
        .map(|(_, v)| v.as_bytes().to_vec())
        .filter(|v| !v.is_empty())
        .collect();

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.stdin(Stdio::inherit());

    let mut child = cmd.spawn().with_context(|| format!("spawn {}", &args[0]))?;
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let sa = secrets.clone();
    let sb = secrets;

    let t1 = std::thread::spawn(move || scrub::copy(&mut out, &mut std::io::stdout(), &sa));
    let t2 = std::thread::spawn(move || scrub::copy(&mut err, &mut std::io::stderr(), &sb));
    let status = child.wait().context("wait child")?;
    let _ = t1.join();
    let _ = t2.join();
    std::process::exit(status.code().unwrap_or(1));
}

fn fmt_duration(secs: u64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}
