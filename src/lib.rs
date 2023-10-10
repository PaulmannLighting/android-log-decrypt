mod encrypted_log;

pub use encrypted_log::EncryptedLog;
use std::str::FromStr;

/// Decrypt encrypted Android logs
///
/// # Errors
/// Returns an [`anyhow::Error`] on errors.
pub fn decrypt(cipher: &str, key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = EncryptedLog::from_str(cipher)?;
    cipher.validate(key)?;
    cipher.decrypt(key)
}
