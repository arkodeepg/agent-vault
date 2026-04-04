// s — encrypted env store with per-entry encryption + multi-host recipients.
//
// `.senv` is a YAML file:
//
//   hosts:
//     laptop:  "ssh-ed25519 AAAA... tobi@laptop"
//     agent:   "ssh-ed25519 AAAA... agent@box"
//   keys:
//     API_KEY: "<base64 age-encrypted blob>"
//     DB_URL:  "<base64 age-encrypted blob>"
//
// * `s add` / `s import` only read `hosts` (public keys). No private key
//   required for appending.
// * `s list / s -- cmd` need an SSH identity that matches a listed host to
//   decrypt. A 7-day session ticket caches the decrypted map so the
//   identity is only needed once per week.
// * `s hosts add/remove` need an SSH identity (to re-wrap every value for
//   the new recipient set).

mod identity;
mod scrub;
mod store;
mod sysinfo;
mod ticket;

use std::io::Write;
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
        "init" => cmd_init(&args[1..]),
        "add" => {
            let (force, pos) = parse_force(&args[1..], "s add [-f] KEY=VALUE")?;
            cmd_add(&pos, force)
        }
        "import" => {
            let (force, pos) = parse_force(&args[1..], "s import [-f] NAME")?;
            cmd_import(&pos, force)
        }
        "list" | "ls" => cmd_list(),
        "unlock" => cmd_unlock(),
        "lock" => cmd_lock(),
        "status" => cmd_status(),
        "hosts" => cmd_hosts(&args[1..]),
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        other => bail!("unknown command: {other} (try `s help`)"),
    }
}

fn print_usage() {
    eprintln!(
        "s — encrypted env store with multi-host recipients\n\n\
         usage:\n  \
         s init [NAME]               create ./{STORE_FILE}, add this host as NAME\n  \
         s add [-f] KEY=VALUE        add a variable (no identity required)\n  \
         s import [-f] NAME          copy $NAME from the current env into the store\n  \
         s list                      list variable names\n  \
         s unlock                    start/refresh 7-day session (uses SSH identity)\n  \
         s lock                      end session (delete ticket)\n  \
         s status                    show store, hosts, session state\n  \
         s hosts                     list authorized hosts\n  \
         s hosts add NAME <key|path> add a recipient, re-wrap all values\n  \
         s hosts remove NAME         remove a recipient, re-wrap all values\n  \
         s -- <cmd> [args...]        run cmd with stored vars in env, scrubbing echoes\n\n\
         env:\n  \
         S_IDENTITY                  path to SSH private key (else ~/.ssh/id_ed25519)\n  \
         S_TICKET_DIR                override where session tickets are stored\n"
    );
}

fn store_path() -> PathBuf {
    PathBuf::from(STORE_FILE)
}

fn parse_force(args: &[String], usage: &'static str) -> Result<(bool, String)> {
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

// --- init -----------------------------------------------------------------

fn cmd_init(args: &[String]) -> Result<()> {
    let path = store_path();
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    let host_name = if let Some(n) = args.first() {
        n.clone()
    } else {
        hostname_default()
    };
    if !store::valid_host_name(&host_name) {
        bail!("invalid host name: {host_name:?}");
    }
    let id_path = identity::discover()?;
    let pubkey = identity::public_key_for(&id_path)?;
    let pubkey = store::validate_pubkey_line(&pubkey)?;

    let mut file = store::SenvFile::default();
    file.hosts.insert(host_name.clone(), pubkey);
    file.save(&path)?;
    eprintln!(
        "s: initialized {} with host {host_name} (identity: {})",
        path.display(),
        id_path.display()
    );
    Ok(())
}

fn hostname_default() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "this-host".to_string())
}

// --- add / import ---------------------------------------------------------

fn cmd_add(pair: &str, force: bool) -> Result<()> {
    let (k, v) = pair.split_once('=').ok_or_else(|| anyhow!("expected KEY=VALUE"))?;
    if !store::valid_key_name(k) {
        bail!("invalid key: {k:?}");
    }
    if v.contains('\n') {
        bail!("value must not contain newlines");
    }

    let path = store_path();
    if !path.exists() {
        bail!("no {STORE_FILE} here — run `s init` first");
    }
    let mut file = store::SenvFile::load(&path)?;
    if file.keys.contains_key(k) && !force && !confirm_overwrite(k)? {
        bail!("aborted");
    }

    let recipients = file.recipients()?;
    let blob = store::encrypt_value(v, recipients)?;
    let verb = if file.keys.contains_key(k) { "updated" } else { "added" };
    file.keys.insert(k.to_string(), blob);
    file.save(&path)?;
    eprintln!("s: {verb} {k}");

    // Invalidate cached ticket — it may have a stale value for this key.
    let _ = ticket::delete(&path);
    Ok(())
}

fn cmd_import(name: &str, force: bool) -> Result<()> {
    if !store::valid_key_name(name) {
        bail!("invalid variable name: {name:?}");
    }
    let v = std::env::var(name)
        .with_context(|| format!("${name} is not set in the current environment"))?;
    let pair = format!("{name}={v}");
    cmd_add(&pair, force)
}

fn confirm_overwrite(key: &str) -> Result<bool> {
    use std::io::{BufRead, BufReader};
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

// --- list / exec / status ------------------------------------------------

fn cmd_list() -> Result<()> {
    let path = store_path();
    if !path.exists() {
        eprintln!("s: no {STORE_FILE} here");
        return Ok(());
    }
    let file = store::SenvFile::load(&path)?;
    if file.keys.is_empty() {
        eprintln!("s: (no keys)");
    } else {
        for k in file.keys.keys() {
            println!("{k}");
        }
    }
    Ok(())
}

fn cmd_exec(args: Vec<String>) -> Result<()> {
    let path = store_path();
    if !path.exists() {
        bail!("no {STORE_FILE} here");
    }
    let entries = decrypt_all(&path)?;

    let mut cmd = Command::new(&args[0]);
    cmd.args(&args[1..]);
    for (k, v) in &entries {
        cmd.env(k, v);
    }

    let secrets: Vec<Vec<u8>> = entries
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

/// Decrypt every `keys` entry. Uses the session ticket if valid; otherwise
/// loads the SSH identity, decrypts, and writes a fresh ticket.
fn decrypt_all(path: &Path) -> Result<Vec<(String, String)>> {
    let file = store::SenvFile::load(path)?;
    let digest = file.hosts_digest();
    if let Some(cached) = ticket::try_load_entries(path, &digest)? {
        return Ok(cached);
    }
    if file.keys.is_empty() {
        // Nothing to decrypt; don't force an identity load.
        ticket::save_entries(path, &digest, &[], Duration::from_secs(TICKET_LIFETIME_SECS))?;
        return Ok(Vec::new());
    }
    let id_path = identity::discover()?;
    let id = identity::load(&id_path)?;
    let mut out: Vec<(String, String)> = Vec::with_capacity(file.keys.len());
    for (k, blob) in &file.keys {
        let v = store::decrypt_value(blob, id.as_age())
            .with_context(|| format!("decrypting {k}"))?;
        out.push((k.clone(), v));
    }
    ticket::save_entries(path, &digest, &out, Duration::from_secs(TICKET_LIFETIME_SECS))?;
    Ok(out)
}

fn cmd_unlock() -> Result<()> {
    let path = store_path();
    if !path.exists() {
        bail!("no {STORE_FILE} here");
    }
    // Force a fresh ticket.
    ticket::delete(&path)?;
    let entries = decrypt_all(&path)?;
    let file = store::SenvFile::load(&path)?;
    let remaining = ticket::remaining_secs(&path, &file.hosts_digest())?.unwrap_or(0);
    eprintln!(
        "s: unlocked ({} entries) — ticket valid for {}",
        entries.len(),
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
        println!("store:   none");
        return Ok(());
    }
    let file = store::SenvFile::load(&path)?;
    println!("store:   {} ({} keys, {} hosts)", path.display(), file.keys.len(), file.hosts.len());
    for (name, pk) in &file.hosts {
        println!("  host {name}: {}", store::fingerprint(pk));
    }
    match ticket::remaining_secs(&path, &file.hosts_digest())? {
        Some(secs) => println!("session: unlocked — {} remaining", fmt_duration(secs)),
        None => println!("session: locked"),
    }
    Ok(())
}

// --- hosts subcommand ----------------------------------------------------

fn cmd_hosts(args: &[String]) -> Result<()> {
    if args.is_empty() {
        return hosts_list();
    }
    match args[0].as_str() {
        "add" => {
            if args.len() != 3 {
                bail!("usage: s hosts add NAME <pubkey|path>");
            }
            hosts_add(&args[1], &args[2])
        }
        "remove" | "rm" => {
            if args.len() != 2 {
                bail!("usage: s hosts remove NAME");
            }
            hosts_remove(&args[1])
        }
        other => bail!("unknown: s hosts {other}"),
    }
}

fn hosts_list() -> Result<()> {
    let path = store_path();
    if !path.exists() {
        bail!("no {STORE_FILE} here");
    }
    let file = store::SenvFile::load(&path)?;
    if file.hosts.is_empty() {
        eprintln!("s: (no hosts)");
        return Ok(());
    }
    for (name, pk) in &file.hosts {
        println!("{name}  {}  {}", store::fingerprint(pk), pk.split_whitespace().next().unwrap_or(""));
    }
    Ok(())
}

fn hosts_add(name: &str, key_or_path: &str) -> Result<()> {
    if !store::valid_host_name(name) {
        bail!("invalid host name: {name:?}");
    }
    let line = if std::path::Path::new(key_or_path).exists() {
        std::fs::read_to_string(key_or_path)
            .with_context(|| format!("reading {key_or_path}"))?
    } else {
        key_or_path.to_string()
    };
    let pubkey = store::validate_pubkey_line(&line)?;

    let path = store_path();
    let mut file = store::SenvFile::load(&path)?;
    if file.hosts.contains_key(name) {
        bail!("host {name} already exists");
    }
    file.hosts.insert(name.to_string(), pubkey);
    rewrap_all(&path, &mut file)?;
    eprintln!("s: added host {name}; re-wrapped {} key(s)", file.keys.len());
    Ok(())
}

fn hosts_remove(name: &str) -> Result<()> {
    let path = store_path();
    let mut file = store::SenvFile::load(&path)?;
    if file.hosts.remove(name).is_none() {
        bail!("no host named {name}");
    }
    if file.hosts.is_empty() {
        bail!("refusing to remove last host (would make the store unrecoverable)");
    }
    rewrap_all(&path, &mut file)?;
    eprintln!("s: removed host {name}; re-wrapped {} key(s)", file.keys.len());
    Ok(())
}

/// Re-encrypt every value in `file.keys` for the current `file.hosts`.
fn rewrap_all(path: &Path, file: &mut store::SenvFile) -> Result<()> {
    if !file.keys.is_empty() {
        // Need to decrypt first — load identity.
        let id_path = identity::discover()?;
        let id = identity::load(&id_path)?;
        let mut plain = std::collections::BTreeMap::new();
        for (k, blob) in &file.keys {
            let v = store::decrypt_value(blob, id.as_age())
                .with_context(|| format!("decrypting {k}"))?;
            plain.insert(k.clone(), v);
        }
        file.keys.clear();
        for (k, v) in &plain {
            let recipients = file.recipients()?;
            let blob = store::encrypt_value(v, recipients)?;
            file.keys.insert(k.clone(), blob);
        }
    }
    file.save(path)?;
    let _ = ticket::delete(path);
    Ok(())
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
