use anyhow::{bail, Context, Result};

/// Prompt for an existing passphrase (or read $S_PASSPHRASE).
pub fn existing(purpose: &str) -> Result<String> {
    if let Ok(p) = std::env::var("S_PASSPHRASE") {
        return Ok(p);
    }
    let prompt = format!("passphrase ({purpose}): ");
    let p = rpassword::prompt_password(&prompt).context("reading passphrase")?;
    if p.is_empty() {
        bail!("empty passphrase");
    }
    Ok(p)
}

/// Prompt (with confirmation) for a new passphrase.
pub fn new() -> Result<String> {
    if let Ok(p) = std::env::var("S_PASSPHRASE") {
        if p.is_empty() {
            bail!("empty passphrase");
        }
        return Ok(p);
    }
    let a = rpassword::prompt_password("new passphrase: ").context("reading passphrase")?;
    if a.is_empty() {
        bail!("empty passphrase");
    }
    let b = rpassword::prompt_password("confirm passphrase: ")?;
    if a != b {
        bail!("passphrases do not match");
    }
    Ok(a)
}
