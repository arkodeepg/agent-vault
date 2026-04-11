// Byte-literal scrubbing of secret values in a stream. Uses a sliding tail
// buffer of (max_secret_len - 1) bytes so a secret straddling two reads is
// still caught on the next pass.

use std::io::{Read, Write};

pub fn copy<R: Read, W: Write>(r: &mut R, w: &mut W, secrets: &[Vec<u8>]) {
    let max_secret = secrets.iter().map(|s| s.len()).max().unwrap_or(0);
    let keep = max_secret.saturating_sub(1);

    let mut buf = vec![0u8; 8192];
    let mut pending: Vec<u8> = Vec::new();

    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        pending.extend_from_slice(&buf[..n]);
        let scrubbed = scrub_bytes(&pending, secrets);
        let flush_up_to = scrubbed.len().saturating_sub(keep);
        let _ = w.write_all(&scrubbed[..flush_up_to]);
        let _ = w.flush();
        pending = scrubbed[flush_up_to..].to_vec();
    }
    let scrubbed = scrub_bytes(&pending, secrets);
    let _ = w.write_all(&scrubbed);
    let _ = w.flush();
}

fn scrub_bytes(hay: &[u8], secrets: &[Vec<u8>]) -> Vec<u8> {
    if secrets.is_empty() {
        return hay.to_vec();
    }
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        let mut matched = None;
        for s in secrets {
            if !s.is_empty() && hay[i..].starts_with(s) {
                matched = Some(s.len());
                break;
            }
        }
        if let Some(len) = matched {
            out.extend_from_slice(b"[REDACTED]");
            i += len;
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}
