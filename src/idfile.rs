//! Persistent per-machine identity stored on disk.
//!
//! Unlike wschat (which takes seeds from env or generates ephemeral ones),
//! usbws is a long-lived daemon that must keep the same keys across restarts
//! so the peer's trust-by-key relationship stays valid. The keypair lives in
//! ~/.config/usbws/identity as two hex32 seeds, mode 0600.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use rand::rngs::OsRng;
use rand::RngCore;

use crate::proto::Identity;

/// Resolve the identity file path: $USBWS_IDENTITY, else
/// $XDG_CONFIG_HOME/usbws/identity, else ~/.config/usbws/identity.
pub fn identity_path() -> PathBuf {
    if let Ok(p) = std::env::var("USBWS_IDENTITY") {
        return PathBuf::from(p);
    }
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".config")
        });
    base.join("usbws").join("identity")
}

/// Load the identity from disk, generating and persisting a fresh keypair on
/// first run. Returns (identity, was_created).
pub fn load_or_create() -> anyhow::Result<(Identity, bool)> {
    let path = identity_path();
    if path.exists() {
        let raw = fs::read_to_string(&path)?;
        let (x_seed, ed_seed) = parse_identity(&raw)
            .ok_or_else(|| anyhow::anyhow!("malformed identity file: {}", path.display()))?;
        return Ok((Identity::from_seeds(x_seed, ed_seed), false));
    }

    // First run: generate, then persist with restrictive permissions.
    let mut x_seed = [0u8; 32];
    let mut ed_seed = [0u8; 32];
    OsRng.fill_bytes(&mut x_seed);
    OsRng.fill_bytes(&mut ed_seed);

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    write_identity(&path, &x_seed, &ed_seed)?;
    Ok((Identity::from_seeds(x_seed, ed_seed), true))
}

/// Parse the on-disk format: two whitespace/`=`-separated hex32 fields.
/// Accepts both bare "hex hex" and "x_seed=hex\ned_seed=hex".
fn parse_identity(raw: &str) -> Option<([u8; 32], [u8; 32])> {
    let mut x_seed: Option<[u8; 32]> = None;
    let mut ed_seed: Option<[u8; 32]> = None;
    let mut bare: Vec<[u8; 32]> = Vec::new();

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(v) = line.strip_prefix("x_seed=") {
            x_seed = decode_hex32(v.trim());
        } else if let Some(v) = line.strip_prefix("ed_seed=") {
            ed_seed = decode_hex32(v.trim());
        } else if let Some(s) = decode_hex32(line) {
            bare.push(s);
        }
    }

    match (x_seed, ed_seed) {
        (Some(x), Some(e)) => Some((x, e)),
        _ if bare.len() >= 2 => Some((bare[0], bare[1])),
        _ => None,
    }
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

fn write_identity(path: &PathBuf, x_seed: &[u8; 32], ed_seed: &[u8; 32]) -> anyhow::Result<()> {
    let body = format!(
        "# usbws machine identity (keep secret)\nx_seed={}\ned_seed={}\n",
        hex::encode(x_seed),
        hex::encode(ed_seed),
    );
    // Create with 0600 from the start so the secret is never world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(body.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        let mut f = fs::File::create(path)?;
        f.write_all(body.as_bytes())?;
    }
    Ok(())
}
