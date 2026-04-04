// .senv v1 binary format:
//
//   magic          "S1\0"                 3 bytes
//   wdk_len        u32 little-endian      4 bytes
//   wrapped_dk     see wrap_dk() below    wdk_len bytes
//   nonce          ChaCha20Poly1305 nonce 12 bytes
//   ciphertext     ChaCha20Poly1305(DK, payload, aad = all preceding bytes)
//
// Two layers:
//   passphrase  --Argon2id--> KEK -> AEAD-wraps DK
//   DK          --ChaCha20Poly1305--> payload
//
// The passphrase never directly encrypts the payload. That gives us a handle
// (DK) we can cache in a session ticket without ever caching the passphrase.
//
// wrapped_dk blob layout (81 bytes, fully self-describing):
//
//   magic "WDK1\0"  5 bytes
//   salt            16 bytes
//   nonce           12 bytes
//   ciphertext      48 bytes  = ChaCha20Poly1305(KEK, DK, aad=prefix)
//
// KEK = Argon2id(passphrase, salt, m=64MiB, t=3, p=1, out=32).

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use std::io::Write;
use std::path::Path;

pub const MAGIC: &[u8; 3] = b"S1\0";
const NONCE_LEN: usize = 12;

pub struct Header {
    pub wrapped_dk: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    /// magic || u32 wdk_len || wrapped_dk || nonce — used as AAD so the
    /// ciphertext is cryptographically bound to the exact wrapped DK.
    pub aad: Vec<u8>,
}

pub fn is_v1(raw: &[u8]) -> bool {
    raw.len() >= MAGIC.len() && &raw[..MAGIC.len()] == MAGIC
}

pub fn parse_header(raw: &[u8]) -> Result<Header> {
    if !is_v1(raw) {
        bail!("not a v1 .senv file");
    }
    if raw.len() < MAGIC.len() + 4 {
        bail!("store truncated at length field");
    }
    let wdk_len =
        u32::from_le_bytes(raw[MAGIC.len()..MAGIC.len() + 4].try_into().unwrap()) as usize;
    if wdk_len > 1 << 20 {
        bail!("implausible wrapped_dk length: {wdk_len}");
    }
    let wdk_start = MAGIC.len() + 4;
    let wdk_end = wdk_start + wdk_len;
    if raw.len() < wdk_end + NONCE_LEN {
        bail!("store truncated before nonce");
    }
    let wrapped_dk = raw[wdk_start..wdk_end].to_vec();
    let nonce_end = wdk_end + NONCE_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&raw[wdk_end..nonce_end]);
    let ciphertext = raw[nonce_end..].to_vec();
    let aad = raw[..nonce_end].to_vec();
    Ok(Header { wrapped_dk, nonce, ciphertext, aad })
}

pub fn decrypt_payload(header: &Header, dk: &[u8; 32]) -> Result<Vec<(String, String)>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(dk));
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&header.nonce),
            Payload { msg: &header.ciphertext, aad: &header.aad },
        )
        .map_err(|_| anyhow!("payload auth failed (wrong DK or tampered store)"))?;
    let text = String::from_utf8(pt).context("payload is not utf-8")?;
    parse_entries(&text)
}

pub fn write_store(
    path: &Path,
    wrapped_dk: &[u8],
    dk: &[u8; 32],
    entries: &[(String, String)],
) -> Result<()> {
    let plain = serialize_entries(entries);
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| anyhow!("getrandom: {e}"))?;

    let wdk_len = u32::try_from(wrapped_dk.len()).map_err(|_| anyhow!("wrapped_dk too large"))?;
    let mut aad = Vec::with_capacity(MAGIC.len() + 4 + wrapped_dk.len() + NONCE_LEN);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&wdk_len.to_le_bytes());
    aad.extend_from_slice(wrapped_dk);
    aad.extend_from_slice(&nonce);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(dk));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: plain.as_bytes(), aad: &aad },
        )
        .map_err(|e| anyhow!("encrypt payload: {e}"))?;

    let mut out = aad; // reuse: aad == magic||len||wdk||nonce, the file prefix
    out.extend_from_slice(&ct);
    atomic_write(path, &out)
}

pub fn new_dk() -> Result<[u8; 32]> {
    let mut dk = [0u8; 32];
    getrandom::getrandom(&mut dk).map_err(|e| anyhow!("getrandom: {e}"))?;
    Ok(dk)
}

// --- passphrase-wrapped DK --------------------------------------------------

const WDK_MAGIC: &[u8; 5] = b"WDK1\0";
const WDK_SALT_LEN: usize = 16;
const WDK_NONCE_LEN: usize = 12;
const WDK_CT_LEN: usize = 48; // 32-byte DK + 16-byte Poly1305 tag
pub const WDK_LEN: usize = WDK_MAGIC.len() + WDK_SALT_LEN + WDK_NONCE_LEN + WDK_CT_LEN;

// Argon2id parameters. These are baked into the format; if we ever need to
// raise them we bump WDK_MAGIC.
const ARGON_M_KIB: u32 = 65_536; // 64 MiB
const ARGON_T: u32 = 3;
const ARGON_P: u32 = 1;

fn derive_kek(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = argon2::Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(32))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut kek = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut kek)
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(kek)
}

pub fn wrap_dk(passphrase: &str, dk: &[u8; 32]) -> Result<Vec<u8>> {
    let mut salt = [0u8; WDK_SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| anyhow!("getrandom: {e}"))?;
    let mut nonce = [0u8; WDK_NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| anyhow!("getrandom: {e}"))?;

    let kek = derive_kek(passphrase, &salt)?;
    let mut prefix = Vec::with_capacity(WDK_MAGIC.len() + WDK_SALT_LEN + WDK_NONCE_LEN);
    prefix.extend_from_slice(WDK_MAGIC);
    prefix.extend_from_slice(&salt);
    prefix.extend_from_slice(&nonce);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: dk, aad: &prefix })
        .map_err(|e| anyhow!("wrap_dk encrypt: {e}"))?;

    let mut out = prefix;
    out.extend_from_slice(&ct);
    debug_assert_eq!(out.len(), WDK_LEN);
    Ok(out)
}

pub fn unwrap_dk(wrapped: &[u8], passphrase: &str) -> Result<[u8; 32]> {
    if wrapped.len() != WDK_LEN || &wrapped[..WDK_MAGIC.len()] != WDK_MAGIC {
        bail!("malformed wrapped_dk blob");
    }
    let salt = &wrapped[WDK_MAGIC.len()..WDK_MAGIC.len() + WDK_SALT_LEN];
    let nonce_start = WDK_MAGIC.len() + WDK_SALT_LEN;
    let nonce = &wrapped[nonce_start..nonce_start + WDK_NONCE_LEN];
    let aad = &wrapped[..nonce_start + WDK_NONCE_LEN];
    let ct = &wrapped[nonce_start + WDK_NONCE_LEN..];

    let kek = derive_kek(passphrase, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    let dk_vec = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| anyhow!("decrypt failed (wrong passphrase?)"))?;
    if dk_vec.len() != 32 {
        bail!("unexpected DK length");
    }
    let mut dk = [0u8; 32];
    dk.copy_from_slice(&dk_vec);
    Ok(dk)
}

pub fn parse_entries(text: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("malformed line {} in store", i + 1))?;
        out.push((k.to_string(), v.to_string()));
    }
    Ok(out)
}

pub fn serialize_entries(entries: &[(String, String)]) -> String {
    let mut s = String::new();
    for (k, v) in entries {
        s.push_str(k);
        s.push('=');
        s.push_str(v);
        s.push('\n');
    }
    s
}

pub fn valid_key(k: &str) -> bool {
    let mut cs = k.chars();
    let Some(first) = cs.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("senv.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
