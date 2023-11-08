mod encrypted_log;

use anyhow::anyhow;
pub use encrypted_log::EncryptedLog;
use hex::FromHex;

/// Decrypt encrypted Android logs
///
/// # Errors
/// Returns an [`anyhow::Error`] on errors.
pub fn decrypt(ciphertext: &str, key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let encrypted_log = EncryptedLog::from_hex(ciphertext)?;

    if !encrypted_log.is_hmac_valid(key)? {
        return Err(anyhow!("Invalid HMAC."));
    }

    Ok(encrypted_log.decrypt(key)?)
}
