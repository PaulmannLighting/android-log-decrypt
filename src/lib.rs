mod encrypted_log;

pub use encrypted_log::EncryptedLog;
use hex::FromHex;

/// Decrypt encrypted Android logs
///
/// # Errors
/// Returns an [`anyhow::Error`] on errors.
pub fn decrypt(cipher: &str, key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let encrypted_log = EncryptedLog::from_hex(cipher)?;
    encrypted_log.validate(key)?;
    encrypted_log.decrypt(key)
}
