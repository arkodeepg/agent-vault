// Session ticket: caches the fully-decrypted set of entries for a store.
//
// File format (binary):
//   magic           "STKT2\0"                        6 bytes
//   salt                                             32 bytes
//   nonce                                            12 bytes
//   expiry_boot_ns  u64 LE                           8 bytes
//   ct_len          u32 LE                           4 bytes
//   ct              ChaCha20Poly1305(TK, kv-serialized, aad = header)
//
// TK = HKDF-SHA256(
//   ikm  = boot_id,
//   salt = ticket.salt,
//   info = "s-ticket-v2|"
//          || sha256(abs_store_path)
//          || "|" || hosts_digest
//          || "|" || uid
// )
//
// Expiry is kernel-sourced (CLOCK_BOOTTIME on Linux, CLOCK_MONOTONIC on
// Darwin), counts through sleep, and is not settable by userspace.
//
// Any host-list change → different `hosts_digest` → different TK →
// existing tickets stop authenticating.

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::sysinfo;

const MAGIC: &[u8; 6] = b"STKT2\0";
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const EXPIRY_LEN: usize = 8;
const CTLEN_LEN: usize = 4;
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN + EXPIRY_LEN + CTLEN_LEN;

pub fn cache_dir() -> PathBuf {
    if let Ok(d) = std::env::var("S_TICKET_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from(std::env::var("HOME").unwrap_or_default()).join("Library/Caches/s")
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(x) = std::env::var("XDG_CACHE_HOME") {
            if !x.is_empty() {
                return PathBuf::from(x).join("s");
            }
        }
        PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".cache/s")
    }
}

fn abs_path(p: &Path) -> PathBuf {
    std::fs::canonicalize(p)
        .or_else(|_| std::path::absolute(p))
        .unwrap_or_else(|_| p.to_path_buf())
}

fn store_hash(store_path: &Path) -> [u8; 32] {
    let abs = abs_path(store_path);
    let mut h = Sha256::new();
    h.update(abs.as_os_str().as_encoded_bytes());
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn ticket_path_for(store_path: &Path) -> PathBuf {
    let h = store_hash(store_path);
    let mut hex = String::with_capacity(64);
    for b in h {
        hex.push_str(&format!("{b:02x}"));
    }
    cache_dir().join(format!("{hex}.ticket"))
}

fn derive_tk(salt: &[u8], store_path: &Path, hosts_digest: &[u8]) -> Result<[u8; 32]> {
    let boot_id = sysinfo::boot_id()?;
    let sh = store_hash(store_path);
    let uid = sysinfo::uid();

    let mut info = Vec::with_capacity(12 + 32 + 1 + hosts_digest.len() + 1 + 4);
    info.extend_from_slice(b"s-ticket-v2|");
    info.extend_from_slice(&sh);
    info.extend_from_slice(b"|");
    info.extend_from_slice(hosts_digest);
    info.extend_from_slice(b"|");
    info.extend_from_slice(&uid.to_le_bytes());

    let hk = Hkdf::<Sha256>::new(Some(salt), &boot_id);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).map_err(|e| anyhow!("HKDF: {e}"))?;
    Ok(okm)
}

/// Try to recover the cached entries. Returns None (and removes the ticket)
/// on any failure: missing, expired, cross-boot, or hosts-list changed.
pub fn try_load_entries(
    store_path: &Path,
    hosts_digest: &[u8],
) -> Result<Option<Vec<(String, String)>>> {
    let p = ticket_path_for(store_path);
    let raw = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow!("reading ticket: {e}")),
    };
    if raw.len() < HEADER_LEN || &raw[..MAGIC.len()] != MAGIC {
        let _ = std::fs::remove_file(&p);
        return Ok(None);
    }

    let salt = &raw[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce_off = MAGIC.len() + SALT_LEN;
    let nonce = &raw[nonce_off..nonce_off + NONCE_LEN];
    let exp_off = nonce_off + NONCE_LEN;
    let expiry =
        u64::from_le_bytes(raw[exp_off..exp_off + EXPIRY_LEN].try_into().unwrap());
    let ctlen_off = exp_off + EXPIRY_LEN;
    let ct_len =
        u32::from_le_bytes(raw[ctlen_off..ctlen_off + CTLEN_LEN].try_into().unwrap()) as usize;

    if raw.len() != HEADER_LEN + ct_len {
        let _ = std::fs::remove_file(&p);
        return Ok(None);
    }
    let aad = &raw[..HEADER_LEN];
    let ct = &raw[HEADER_LEN..];

    let now = sysinfo::boot_clock_ns()?;
    if now >= expiry {
        let _ = std::fs::remove_file(&p);
        return Ok(None);
    }

    let tk = derive_tk(salt, store_path, hosts_digest)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&tk));
    let pt = match cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad }) {
        Ok(v) => v,
        Err(_) => {
            let _ = std::fs::remove_file(&p);
            return Ok(None);
        }
    };
    let text = match std::str::from_utf8(&pt) {
        Ok(s) => s,
        Err(_) => {
            let _ = std::fs::remove_file(&p);
            return Ok(None);
        }
    };
    Ok(Some(parse_kv(text)))
}

pub fn save_entries(
    store_path: &Path,
    hosts_digest: &[u8],
    entries: &[(String, String)],
    lifetime: Duration,
) -> Result<()> {
    let p = ticket_path_for(store_path);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| anyhow!("getrandom: {e}"))?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| anyhow!("getrandom: {e}"))?;

    let now = sysinfo::boot_clock_ns()?;
    let life_ns = lifetime.as_secs().saturating_mul(1_000_000_000);
    let expiry = now.saturating_add(life_ns);

    let kv = serialize_kv(entries);
    let ct_len: u32 = (kv.len() + 16)
        .try_into()
        .map_err(|_| anyhow!("ticket payload too large"))?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&expiry.to_le_bytes());
    header.extend_from_slice(&ct_len.to_le_bytes());

    let tk = derive_tk(&salt, store_path, hosts_digest)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&tk));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: kv.as_bytes(), aad: &header })
        .map_err(|e| anyhow!("encrypt ticket: {e}"))?;

    let mut out = header;
    out.extend_from_slice(&ct);

    let tmp = p.with_extension("tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).with_context(|| format!("open {}", tmp.display()))?;
        f.write_all(&out)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &p).context("rename ticket")?;
    Ok(())
}

pub fn delete(store_path: &Path) -> Result<()> {
    let p = ticket_path_for(store_path);
    match std::fs::remove_file(&p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!("removing ticket: {e}")),
    }
}

pub fn remaining_secs(store_path: &Path, hosts_digest: &[u8]) -> Result<Option<u64>> {
    let p = ticket_path_for(store_path);
    let raw = match std::fs::read(&p) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    if raw.len() < HEADER_LEN || &raw[..MAGIC.len()] != MAGIC {
        return Ok(None);
    }
    let salt = &raw[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce_off = MAGIC.len() + SALT_LEN;
    let nonce = &raw[nonce_off..nonce_off + NONCE_LEN];
    let exp_off = nonce_off + NONCE_LEN;
    let expiry =
        u64::from_le_bytes(raw[exp_off..exp_off + EXPIRY_LEN].try_into().unwrap());
    let ctlen_off = exp_off + EXPIRY_LEN;
    let ct_len =
        u32::from_le_bytes(raw[ctlen_off..ctlen_off + CTLEN_LEN].try_into().unwrap()) as usize;
    if raw.len() != HEADER_LEN + ct_len {
        return Ok(None);
    }
    let aad = &raw[..HEADER_LEN];
    let ct = &raw[HEADER_LEN..];

    let now = sysinfo::boot_clock_ns()?;
    if now >= expiry {
        return Ok(None);
    }
    let tk = derive_tk(salt, store_path, hosts_digest)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&tk));
    if cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .is_err()
    {
        return Ok(None);
    }
    Ok(Some((expiry - now) / 1_000_000_000))
}

fn serialize_kv(entries: &[(String, String)]) -> String {
    let mut s = String::new();
    for (k, v) in entries {
        s.push_str(k);
        s.push('=');
        s.push_str(v);
        s.push('\n');
    }
    s
}

fn parse_kv(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            out.push((k.to_string(), v.to_string()));
        }
    }
    out
}
