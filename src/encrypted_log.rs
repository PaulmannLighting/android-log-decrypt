mod header;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::KeyIvInit;
use aes::Aes256;
use anyhow::anyhow;
use cbc::cipher::BlockDecryptMut;
use cbc::Decryptor;
use header::{Header, SIZE};
use hex::{FromHex, ToHex};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// An encrypted log file
#[derive(Debug, Eq, PartialEq)]
pub struct EncryptedLog {
    header: Header,
    ciphertext: Vec<u8>,
}

impl EncryptedLog {
    /// Creates a new encrypted log file from a header and ciphertext
    #[must_use]
    pub const fn new(header: Header, ciphertext: Vec<u8>) -> Self {
        Self { header, ciphertext }
    }

    /// Validates the HMAC checksum
    ///
    /// # Errors
    /// Returns an [`anyhow::Error`] on errors.
    pub fn validate(&self, key: &[u8]) -> anyhow::Result<()> {
        if self.calculate_hmac(key)? == self.header.hmac() {
            Ok(())
        } else {
            Err(anyhow!("Invalid HMAC"))
        }
    }

    /// Decrypts the ciphertext
    ///
    /// # Errors
    /// Returns an [`anyhow::Error`] on errors.
    pub fn decrypt(mut self, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(
            Decryptor::<Aes256>::new(key.into(), self.header.iv().into())
                .decrypt_padded_mut::<Pkcs7>(&mut self.ciphertext)
                .map_err(|error| anyhow!("{error}"))?
                .to_vec(),
        )
    }

    fn calculate_hmac(&self, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.header.key().encode_hex::<String>().as_bytes())?;
        mac.update(self.header.iv().encode_hex::<String>().as_bytes());
        mac.update(self.ciphertext.encode_hex::<String>().as_bytes());
        mac.update(key.encode_hex::<String>().as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

impl FromHex for EncryptedLog {
    type Error = anyhow::Error;

    fn from_hex<T>(hex: T) -> Result<Self, Self::Error>
    where
        T: AsRef<[u8]>,
    {
        Self::try_from(Vec::<u8>::from_hex(hex.as_ref())?.as_slice())
    }
}

impl TryFrom<&[u8]> for EncryptedLog {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() > SIZE {
            Ok(Self::new(
                Header::from(<[u8; SIZE]>::try_from(&bytes[0..SIZE])?),
                bytes[SIZE..].to_vec(),
            ))
        } else {
            Err(anyhow!("Too few bytes: {}", bytes.len()))
        }
    }
}
