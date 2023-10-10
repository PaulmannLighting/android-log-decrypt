mod cipher;

use cipher::Cipher;
use std::str::FromStr;

/// Decrypt encrypted Android logs
///
/// # Errors
/// Returns an [`anyhow::Error`] on errors.
pub fn decrypt(cipher: &str, key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Cipher::from_str(cipher)?;
    cipher.validate(key)?;
    cipher.decrypt(key)
}
