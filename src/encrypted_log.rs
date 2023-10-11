mod header;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::KeyIvInit;
use aes::Aes256;
use anyhow::anyhow;
use cbc::cipher::BlockDecryptMut;
use cbc::Decryptor;
use header::{Header, HEADER_HEX_LEN};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs::read_to_string;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Eq, PartialEq)]
pub struct EncryptedLog {
    header: Header,
    ciphertext: Vec<u8>,
}

impl EncryptedLog {
    #[must_use]
    pub const fn new(header: Header, ciphertext: Vec<u8>) -> Self {
        Self { header, ciphertext }
    }

    /// Validates the HMAC checksum
    ///
    /// # Errors
    /// Returns an [`anyhow::Error`] on errors.
    pub fn validate(&self, key: &[u8]) -> anyhow::Result<()> {
        let mut mac = Hmac::<Sha256>::new_from_slice(hex::encode(self.header.key()).as_bytes())?;
        mac.update(hex::encode(self.hash_data(key)).as_bytes());
        let bytes: Vec<u8> = mac.finalize().into_bytes().into_iter().collect();
        if bytes == self.header.hmac() {
            Ok(())
        } else {
            Err(anyhow!("Invalid HMAC"))
        }
    }

    /// Decrypts the ciphertext
    ///
    /// # Errors
    /// Returns an [`anyhow::Error`] on errors.
    pub fn decrypt(&self, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut buf = self.ciphertext.clone();
        let cipher = Decryptor::<Aes256>::new(key.into(), self.header.iv().into());
        Ok(cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|error| anyhow!("{error}"))?
            .to_vec())
    }

    fn hash_data(&self, key: &[u8]) -> Vec<u8> {
        self.header
            .iv()
            .iter()
            .chain(self.ciphertext.iter())
            .chain(key.iter())
            .copied()
            .collect()
    }
}

impl FromStr for EncryptedLog {
    type Err = anyhow::Error;

    fn from_str(ciphertext: &str) -> Result<Self, Self::Err> {
        if ciphertext.len() > HEADER_HEX_LEN {
            Ok(Self::new(
                Header::from_str(&ciphertext[0..HEADER_HEX_LEN])?,
                hex::decode(&ciphertext[HEADER_HEX_LEN..])?,
            ))
        } else {
            Err(anyhow!("Cipher text too short: {}", ciphertext.len()))
        }
    }
}

impl TryFrom<String> for EncryptedLog {
    type Error = anyhow::Error;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::from_str(&text)
    }
}

impl TryFrom<PathBuf> for EncryptedLog {
    type Error = anyhow::Error;

    fn try_from(filename: PathBuf) -> Result<Self, Self::Error> {
        Self::try_from(read_to_string(filename)?)
    }
}
