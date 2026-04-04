// .senv is a YAML file with two maps:
//
//   hosts: { <host-name>: "<ssh-ed25519 AAAA... comment>" }
//   keys:  { <KEY_NAME>:  "<base64 of age-encrypted value>" }
//
// Each value under `keys` is independently encrypted (age) to every recipient
// under `hosts`. This means:
//
//   * `s add` only needs the public keys in `hosts` to write a new entry
//     — no SSH private key required for adding.
//   * `s list / s --` need an SSH private key that matches one of the hosts
//     to decrypt the values.
//   * `s hosts add/remove` needs an SSH private key (to re-wrap every
//     existing value for the updated recipient set).

use anyhow::{anyhow, bail, Context, Result};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::iter;
use std::path::Path;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SenvFile {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub hosts: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<String, String>,
}

impl SenvFile {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let f: SenvFile = serde_yaml::from_str(&raw)
            .with_context(|| format!("parsing YAML in {}", path.display()))?;
        Ok(f)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let yaml = serde_yaml::to_string(self).context("serializing YAML")?;
        let tmp = path.with_extension("senv.tmp");
        std::fs::write(&tmp, yaml.as_bytes()).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).context("rename .senv into place")?;
        Ok(())
    }

    /// Build an age recipient list from the `hosts` map.
    pub fn recipients(&self) -> Result<Vec<Box<dyn age::Recipient + Send>>> {
        if self.hosts.is_empty() {
            bail!("no hosts configured (run `s init` or `s hosts add`)");
        }
        let mut out: Vec<Box<dyn age::Recipient + Send>> = Vec::with_capacity(self.hosts.len());
        for (name, line) in &self.hosts {
            let r: age::ssh::Recipient = line
                .parse()
                .map_err(|e| anyhow!("host {name}: unparseable pubkey: {e:?}"))?;
            out.push(Box::new(r));
        }
        Ok(out)
    }

    /// Deterministic byte summary of the hosts block — used as ticket-key
    /// input so any host change invalidates cached tickets.
    pub fn hosts_digest(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for (name, pk) in &self.hosts {
            h.update(name.as_bytes());
            h.update(b"\0");
            h.update(pk.as_bytes());
            h.update(b"\n");
        }
        h.finalize().to_vec()
    }
}

/// Encrypt a value to all recipients, returning base64(age-ciphertext).
pub fn encrypt_value(value: &str, recipients: Vec<Box<dyn age::Recipient + Send>>) -> Result<String> {
    let refs: Vec<&dyn age::Recipient> = recipients.iter().map(|r| r.as_ref() as &dyn age::Recipient).collect();
    let encryptor = age::Encryptor::with_recipients(refs.into_iter())
        .map_err(|e| anyhow!("encryptor: {e:?}"))?;
    let mut out = Vec::new();
    let mut w = encryptor.wrap_output(&mut out).context("age encryptor init")?;
    w.write_all(value.as_bytes())?;
    w.finish().context("age finish")?;
    Ok(BASE64_STANDARD.encode(&out))
}

/// Decrypt a base64(age-ciphertext) using a single SSH identity.
pub fn decrypt_value(blob_b64: &str, identity: &dyn age::Identity) -> Result<String> {
    let blob = BASE64_STANDARD
        .decode(blob_b64.trim().as_bytes())
        .context("base64 decode of value")?;
    let decryptor = age::Decryptor::new(&blob[..]).context("parsing age blob")?;
    let mut r = decryptor
        .decrypt(iter::once(identity))
        .map_err(|e| anyhow!("age decrypt failed: {e:?}"))?;
    let mut s = String::new();
    r.read_to_string(&mut s).context("reading plaintext")?;
    Ok(s)
}

// --- validation -----------------------------------------------------------

pub fn valid_key_name(k: &str) -> bool {
    let mut cs = k.chars();
    let Some(first) = cs.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn valid_host_name(n: &str) -> bool {
    !n.is_empty()
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Strip an authorized_keys line to a canonical "type base64" form and a
/// display comment. Verifies it's parseable as an age ssh-ed25519 recipient.
pub fn validate_pubkey_line(line: &str) -> Result<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        bail!("empty public key");
    }
    if !trimmed.starts_with("ssh-ed25519 ") {
        bail!("only ssh-ed25519 keys are supported");
    }
    let _: age::ssh::Recipient = trimmed
        .parse()
        .map_err(|e| anyhow!("invalid ssh-ed25519 key: {e:?}"))?;
    Ok(trimmed.to_string())
}

/// Short display fingerprint of an ssh pubkey line: SHA256 of the decoded key
/// blob, truncated and base64'd. Matches what `ssh-keygen -lf` prints.
pub fn fingerprint(line: &str) -> String {
    use sha2::{Digest, Sha256};
    let blob = line
        .split_whitespace()
        .nth(1)
        .and_then(|b64| BASE64_STANDARD.decode(b64.as_bytes()).ok())
        .unwrap_or_default();
    let h = Sha256::digest(&blob);
    let b64 = BASE64_STANDARD.encode(h);
    format!("SHA256:{}", b64.trim_end_matches('='))
}
