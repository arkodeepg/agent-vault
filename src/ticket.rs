// Session ticket: caches the store's data key (DK) for a bounded time.
//
// File format (binary):
//   magic           "STKT1\0"                     6 bytes
//   salt            per-ticket random             32 bytes
//   nonce           AEAD nonce                    12 bytes
//   expiry_boot_ns  kernel boot-clock deadline    8 bytes (u64 LE)
//   ciphertext      ChaCha20Poly1305(TK, DK, aad = all preceding bytes)
//
// Key schedule:
//   TK = HKDF-SHA256(
//     ikm  = boot_id,                // rotates at reboot
//     salt = ticket.salt,
//     info = "s-ticket-v1|" || sha256(abs_store_path)
//                          || "|" || sha256(wrapped_dk)
//                          || "|" || uid
//   )
//
// Expiry has two layers of enforcement, both kernel-sourced:
//   1. reboot -> boot_id changes -> TK unrecoverable -> AEAD auth fails
//   2. elapsed boot-clock time >= expiry_boot_ns -> refused
//      (BOOTTIME/Darwin MONOTONIC is not settable by userspace)
//
// expiry_boot_ns is also mixed into the AAD, so you can't edit it in the file
// without breaking authentication.

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

const MAGIC: &[u8; 6] = b"STKT1\0";
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const EXPIRY_LEN: usize = 8;
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN + EXPIRY_LEN;
// ChaCha20Poly1305 of a 32-byte DK is 48 bytes (32 + 16-byte tag).
const CT_LEN: usize = 48;
const TOTAL_LEN: usize = HEADER_LEN + CT_LEN;

pub fn cache_dir() -> PathBuf {
    // Explicit override wins — used by tests/examples and power users who
    // want the ticket on a specific tmpfs.
    if let Ok(d) = std::env::var("S_TICKET_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(home).join("Library/Caches/s")
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(x) = std::env::var("XDG_CACHE_HOME") {
            if !x.is_empty() {
                return PathBuf::from(x).join("s");
            }
        }
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(home).join(".cache/s")
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
    let hash = store_hash(store_path);
    cache_dir().join(format!("{}.ticket", hex(&hash)))
}

fn derive_tk(salt: &[u8], store_path: &Path, wrapped_dk: &[u8]) -> Result<[u8; 32]> {
    let boot_id = sysinfo::boot_id()?;
    let sh = store_hash(store_path);
    let mut wh = Sha256::new();
    wh.update(wrapped_dk);
    let wh = wh.finalize();
    let uid = sysinfo::uid();

    let mut info = Vec::with_capacity(12 + 32 + 1 + 32 + 1 + 4);
    info.extend_from_slice(b"s-ticket-v1|");
    info.extend_from_slice(&sh);
    info.extend_from_slice(b"|");
    info.extend_from_slice(&wh);
    info.extend_from_slice(b"|");
    info.extend_from_slice(&uid.to_le_bytes());

    let hk = Hkdf::<Sha256>::new(Some(salt), &boot_id);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).map_err(|e| anyhow!("HKDF expand: {e}"))?;
    Ok(okm)
}

/// Try to recover DK from an on-disk ticket. Returns None (and removes the
/// ticket file) for every failure mode: missing, malformed, expired, or
/// cross-boot (AEAD auth fails).
pub fn try_load_dk(store_path: &Path, wrapped_dk: &[u8]) -> Result<Option<[u8; 32]>> {
    let p = ticket_path_for(store_path);
    let raw = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow!("reading ticket: {e}")),
    };
    if raw.len() != TOTAL_LEN || &raw[..MAGIC.len()] != MAGIC {
        let _ = std::fs::remove_file(&p);
        return Ok(None);
    }

    let salt = &raw[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce_start = MAGIC.len() + SALT_LEN;
    let nonce = &raw[nonce_start..nonce_start + NONCE_LEN];
    let expiry_start = nonce_start + NONCE_LEN;
    let expiry = u64::from_le_bytes(
        raw[expiry_start..expiry_start + EXPIRY_LEN].try_into().unwrap(),
    );
    let aad = &raw[..HEADER_LEN];
    let ct = &raw[HEADER_LEN..];

    let now = sysinfo::boot_clock_ns()?;
    if now >= expiry {
        let _ = std::fs::remove_file(&p);
        return Ok(None);
    }

    let tk = derive_tk(salt, store_path, wrapped_dk)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&tk));
    let dk_vec = match cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad }) {
        Ok(v) => v,
        Err(_) => {
            // After reboot boot_id differs → TK differs → auth fails.
            let _ = std::fs::remove_file(&p);
            return Ok(None);
        }
    };
    if dk_vec.len() != 32 {
        let _ = std::fs::remove_file(&p);
        return Ok(None);
    }
    let mut dk = [0u8; 32];
    dk.copy_from_slice(&dk_vec);
    Ok(Some(dk))
}

/// Write a fresh ticket with `now_boot + lifetime` as the deadline.
pub fn save_dk(
    store_path: &Path,
    wrapped_dk: &[u8],
    dk: &[u8; 32],
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

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&expiry.to_le_bytes());

    let tk = derive_tk(&salt, store_path, wrapped_dk)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&tk));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: dk, aad: &header })
        .map_err(|e| anyhow!("encrypt ticket: {e}"))?;

    let mut out = header;
    out.extend_from_slice(&ct);
    debug_assert_eq!(out.len(), TOTAL_LEN);

    // Atomic 0600 write.
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
    std::fs::rename(&tmp, &p).context("rename ticket into place")?;
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

/// Returns seconds remaining if a valid ticket exists for this store, else None.
/// Performs the full AEAD verify so the result reflects crypto validity, not
/// just the filesystem.
pub fn remaining_secs(store_path: &Path, wrapped_dk: &[u8]) -> Result<Option<u64>> {
    let p = ticket_path_for(store_path);
    let raw = match std::fs::read(&p) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    if raw.len() != TOTAL_LEN || &raw[..MAGIC.len()] != MAGIC {
        return Ok(None);
    }
    let salt = &raw[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce_start = MAGIC.len() + SALT_LEN;
    let nonce = &raw[nonce_start..nonce_start + NONCE_LEN];
    let expiry_start = nonce_start + NONCE_LEN;
    let expiry = u64::from_le_bytes(
        raw[expiry_start..expiry_start + EXPIRY_LEN].try_into().unwrap(),
    );
    let aad = &raw[..HEADER_LEN];
    let ct = &raw[HEADER_LEN..];

    let now = sysinfo::boot_clock_ns()?;
    if now >= expiry {
        return Ok(None);
    }
    let tk = derive_tk(salt, store_path, wrapped_dk)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&tk));
    if cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .is_err()
    {
        return Ok(None);
    }
    Ok(Some((expiry - now) / 1_000_000_000))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
