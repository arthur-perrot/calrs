//! Symmetric encryption for stored credentials (CalDAV passwords, SMTP passwords).
//!
//! Uses AES-256-GCM with a random 12-byte nonce per encryption. The encrypted
//! format stored in the database is: base64(nonce || ciphertext || tag).
//!
//! The secret key is loaded from (in order of priority):
//! 1. `CALRS_SECRET_KEY` environment variable (base64-encoded 32 bytes)
//! 2. `secret.key` file in the data directory (raw 32 bytes)
//! 3. Auto-generated and written to `secret.key` on first run

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use base64::Engine;
use rand::RngCore;
use std::path::Path;
use zeroize::Zeroizing;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_FILE: &str = "secret.key";

/// Load or generate the 256-bit secret key.
///
/// Heap intermediates that briefly hold key bytes (decoded env value, file
/// contents) are wrapped in `Zeroizing` so they are wiped on drop instead of
/// being left in freed memory.
pub fn load_or_create_key(data_dir: &Path) -> Result<[u8; KEY_LEN]> {
    // 1. Check env var
    if let Ok(val) = std::env::var("CALRS_SECRET_KEY") {
        let bytes = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(val.trim())
                .context("CALRS_SECRET_KEY must be valid base64")?,
        );
        if bytes.len() != KEY_LEN {
            bail!(
                "CALRS_SECRET_KEY must decode to exactly 32 bytes (got {})",
                bytes.len()
            );
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    // 2. Check key file
    let key_path = data_dir.join(KEY_FILE);
    if key_path.exists() {
        let bytes = Zeroizing::new(
            std::fs::read(&key_path)
                .with_context(|| format!("Failed to read {}", key_path.display()))?,
        );
        if bytes.len() != KEY_LEN {
            bail!(
                "Secret key file has wrong size ({} bytes, expected {})",
                bytes.len(),
                KEY_LEN
            );
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    // 3. Generate new key
    let mut key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    std::fs::create_dir_all(data_dir)?;
    std::fs::write(&key_path, key)
        .with_context(|| format!("Failed to write {}", key_path.display()))?;

    // Set file permissions to 0600 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(key)
}

/// Encrypt a plaintext password. Returns a base64 string (nonce || ciphertext).
pub fn encrypt_password(key: &[u8; KEY_LEN], plaintext: &str) -> Result<String> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("cipher init: {}", e))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

    // nonce || ciphertext (which includes the GCM tag)
    let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
}

/// Decrypt a password stored as base64(nonce || ciphertext).
pub fn decrypt_password(key: &[u8; KEY_LEN], stored: &str) -> Result<String> {
    let combined = base64::engine::general_purpose::STANDARD
        .decode(stored.trim())
        .context("invalid base64 in stored password")?;

    if combined.len() < NONCE_LEN + 1 {
        bail!("stored password too short to contain nonce + ciphertext");
    }

    let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("cipher init: {}", e))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("decryption failed (wrong key?): {}", e))?;

    String::from_utf8(plaintext).context("decrypted password is not valid UTF-8")
}

/// Check if a stored value looks like a legacy hex-encoded password
/// (as opposed to base64-encoded encrypted data).
/// Legacy format: hex-encoded ASCII bytes → always even length, only [0-9a-f].
pub fn is_legacy_hex(value: &str) -> bool {
    !value.is_empty()
        && value.len().is_multiple_of(2)
        && value.chars().all(|c| c.is_ascii_hexdigit())
        // base64 can also be all hex chars, but legacy hex-encoded passwords
        // produce longer strings (2 chars per byte vs ~1.33 for base64).
        // A hex-encoded password of length N produces 2N hex chars.
        // Decrypt attempt will fail on non-legacy data, so this is just a heuristic.
        && hex::decode(value)
            .map(|bytes| String::from_utf8(bytes).is_ok())
            .unwrap_or(false)
}

/// Migrate a legacy hex-encoded password to encrypted format.
/// Returns the encrypted string if it was legacy, None otherwise.
pub fn migrate_legacy(key: &[u8; KEY_LEN], stored: &str) -> Result<Option<String>> {
    if is_legacy_hex(stored) {
        let bytes = hex::decode(stored)?;
        let plaintext = String::from_utf8(bytes)?;
        let encrypted = encrypt_password(key, &plaintext)?;
        Ok(Some(encrypted))
    } else {
        Ok(None)
    }
}

/// Sentinel prefix for encrypted values stored in fields where the plaintext
/// can otherwise look like base64 (e.g. an OIDC client secret). The prefix
/// lets the migration tell encrypted from plaintext at a glance, without
/// needing structural heuristics that could false-positive.
const ENC_PREFIX: &str = "enc:v1:";

/// Whether a stored value is in the prefixed-encrypted format.
pub fn is_encrypted_value(stored: &str) -> bool {
    stored.starts_with(ENC_PREFIX)
}

/// Encrypt a value with a sentinel prefix so the encrypted form is
/// unambiguously distinguishable from plaintext.
pub fn encrypt_value(key: &[u8; KEY_LEN], plaintext: &str) -> Result<String> {
    let body = encrypt_password(key, plaintext)?;
    Ok(format!("{}{}", ENC_PREFIX, body))
}

/// Decrypt a value previously produced by `encrypt_value`. Errors if the
/// value lacks the expected prefix or fails AES-GCM decryption.
pub fn decrypt_value(key: &[u8; KEY_LEN], stored: &str) -> Result<String> {
    let body = stored
        .strip_prefix(ENC_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("not in encrypted-value format"))?;
    decrypt_password(key, body)
}

#[cfg(test)]
mod tests;
