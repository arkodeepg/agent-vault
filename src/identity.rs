// SSH identity discovery and loading.
//
// We look for an OpenSSH ed25519 private key (+ its .pub) in this order:
//   1. $S_IDENTITY
//   2. $HOME/.ssh/id_ed25519
//   3. $HOME/.ssh/hostkey
//
// Passphrase-protected keys are prompted for via rpassword.

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

pub struct Identity {
    pub inner: age::ssh::Identity,
    #[allow(dead_code)]
    pub source: PathBuf,
}

impl Identity {
    pub fn as_age(&self) -> &dyn age::Identity {
        &self.inner
    }
}

pub fn discover() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("S_IDENTITY") {
        if !p.is_empty() {
            let pb = PathBuf::from(&p);
            if !pb.exists() {
                bail!("$S_IDENTITY={p} does not exist");
            }
            return Ok(pb);
        }
    }
    let home = std::env::var("HOME").context("no $HOME")?;
    for name in ["id_ed25519", "hostkey"] {
        let pb = PathBuf::from(&home).join(".ssh").join(name);
        if pb.exists() {
            return Ok(pb);
        }
    }
    bail!("no SSH identity found. Set $S_IDENTITY or create ~/.ssh/id_ed25519")
}

pub fn public_key_for(private_path: &Path) -> Result<String> {
    // Convention: "<path>.pub".
    let pub_path = {
        let mut s = private_path.as_os_str().to_owned();
        s.push(".pub");
        PathBuf::from(s)
    };
    let raw = std::fs::read_to_string(&pub_path)
        .with_context(|| format!("reading {}", pub_path.display()))?;
    Ok(raw.trim().to_string())
}

pub fn load(path: &Path) -> Result<Identity> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let filename = path.to_string_lossy().into_owned();
    let parsed = age::ssh::Identity::from_buffer(raw.as_bytes(), Some(filename))
        .with_context(|| format!("parsing {} as SSH key", path.display()))?;
    let unlocked = match parsed {
        age::ssh::Identity::Unencrypted(_) => parsed,
        age::ssh::Identity::Encrypted(enc) => {
            let prompt = format!("passphrase for {}: ", path.display());
            let pp = rpassword::prompt_password(&prompt).context("reading SSH key passphrase")?;
            let secret = age::secrecy::SecretString::from(pp);
            let unenc = enc
                .decrypt(secret)
                .map_err(|_| anyhow!("wrong passphrase for {}", path.display()))?;
            age::ssh::Identity::Unencrypted(unenc)
        }
        age::ssh::Identity::Unsupported(kind) => {
            bail!("unsupported SSH key type in {}: {kind:?}", path.display())
        }
    };
    Ok(Identity { inner: unlocked, source: path.to_path_buf() })
}
