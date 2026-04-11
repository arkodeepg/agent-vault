// .senv — YAML with symmetric-encrypted values.
//
// keys:
//   API_KEY: "salt:nonce:ciphertext"        # base64-encoded
//   STRIPE_KEY:
//     value: "salt:nonce:ciphertext"
//     history:
//       - blob: "salt:nonce:ciphertext"
//         ts: "2026-04-11T14:30Z"
//
// Each value is independently encrypted with ChaCha20-Poly1305.
// Key = HKDF-SHA256(password, per-value random salt).
// No recipient field — whoever has the password can decrypt.

use anyhow::{bail, Context, Result};
use base64::prelude::*;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::path::Path;

const MAX_HISTORY: usize = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SenvFile {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<String, KeyEntry>,
}

/// Bare string for simple keys, struct when history exists.
#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum KeyEntry {
    Simple(String),
    WithHistory {
        value: String,
        history: Vec<HistoryEntry>,
    },
}

impl KeyEntry {
    pub fn value(&self) -> &str {
        match self {
            KeyEntry::Simple(v) => v,
            KeyEntry::WithHistory { value, .. } => value,
        }
    }

    pub fn history(&self) -> &[HistoryEntry] {
        match self {
            KeyEntry::Simple(_) => &[],
            KeyEntry::WithHistory { history, .. } => history,
        }
    }

    pub fn update(&mut self, new_blob: String) {
        let old = self.value().to_string();
        let mut hist: Vec<HistoryEntry> = self.history().to_vec();
        hist.insert(0, HistoryEntry { blob: old, ts: now_iso() });
        hist.truncate(MAX_HISTORY);
        *self = KeyEntry::WithHistory { value: new_blob, history: hist };
    }

    pub fn rollback(&mut self, n: usize) -> Result<()> {
        let hist = self.history().to_vec();
        if n == 0 || n > hist.len() {
            bail!("version {n} not found ({} in history)", hist.len());
        }
        let old_current = self.value().to_string();
        let mut hist = hist;
        let restored = hist.remove(n - 1);
        hist.insert(0, HistoryEntry { blob: old_current, ts: now_iso() });
        hist.truncate(MAX_HISTORY);
        *self = KeyEntry::WithHistory { value: restored.blob, history: hist };
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HistoryEntry {
    pub blob: String,
    pub ts: String,
}

impl SenvFile {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_yaml::from_str(&raw)
            .with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let yaml = serde_yaml::to_string(self).context("serializing YAML")?;
        let tmp = path.with_extension("senv.tmp");
        std::fs::write(&tmp, yaml.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).context("rename .senv into place")?;
        Ok(())
    }

    pub fn set_key(&mut self, key: &str, blob: String) {
        if let Some(entry) = self.keys.get_mut(key) {
            entry.update(blob);
        } else {
            self.keys.insert(key.to_string(), KeyEntry::Simple(blob));
        }
    }
}

// --- Symmetric encryption -------------------------------------------------
//
// Format: base64( salt[16] || nonce[12] || ciphertext )
// Key derivation: HKDF-SHA256(ikm=password, salt=salt, info="s-v1")

pub fn encrypt_value(plaintext: &str, password: &str) -> Result<String> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;

    let dk = derive_key(password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dk));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;

    let mut packed = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
    packed.extend_from_slice(&salt);
    packed.extend_from_slice(&nonce_bytes);
    packed.extend_from_slice(&ct);
    Ok(BASE64_STANDARD.encode(&packed))
}

pub fn decrypt_value(blob_b64: &str, password: &str) -> Result<String> {
    let packed = BASE64_STANDARD.decode(blob_b64.trim().as_bytes())
        .context("base64 decode")?;
    if packed.len() < SALT_LEN + NONCE_LEN + 16 {
        bail!("blob too short");
    }
    let salt = &packed[..SALT_LEN];
    let nonce = &packed[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ct = &packed[SALT_LEN + NONCE_LEN..];

    let dk = derive_key(password, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dk));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| anyhow::anyhow!("decryption failed (wrong password?)"))?;
    String::from_utf8(pt).context("plaintext is not UTF-8")
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"s-v1", &mut okm).map_err(|e| anyhow::anyhow!("HKDF: {e}"))?;
    Ok(okm)
}

// --- Validation -----------------------------------------------------------

pub fn valid_key_name(k: &str) -> bool {
    let mut cs = k.chars();
    let Some(first) = cs.next() else { return false };
    (first.is_ascii_alphabetic() || first == '_')
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn now_iso() -> String {
    use std::process::Command;
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
