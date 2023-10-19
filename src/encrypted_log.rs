mod header;

use aes::cipher::block_padding::{Pkcs7, UnpadError};
use aes::cipher::KeyIvInit;
use aes::Aes256;
use anyhow::anyhow;
use cbc::cipher::BlockDecryptMut;
use cbc::Decryptor;
use header::{Header, SIZE};
use hex::{FromHex, ToHex};
use hmac::digest::InvalidLength;
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
    /// Returns [`InvalidLength`] on errors.
    pub fn validate(&self, key: &[u8]) -> Result<bool, InvalidLength> {
        Ok(self.calculate_hmac(key)? == self.header.hmac())
    }

    /// Decrypts the ciphertext
    ///
    /// # Errors
    /// Returns an [`UnpadError`] on errors.
    pub fn decrypt(mut self, key: &[u8]) -> Result<Vec<u8>, UnpadError> {
        Decryptor::<Aes256>::new(key.into(), self.header.iv().into())
            .decrypt_padded_mut::<Pkcs7>(&mut self.ciphertext)
            .map(<[u8]>::to_vec)
    }

    fn calculate_hmac(&self, key: &[u8]) -> Result<Vec<u8>, InvalidLength> {
        Hmac::<Sha256>::new_from_slice(self.header.key().encode_hex::<String>().as_bytes()).map(
            |mut mac| {
                mac.update(self.header.iv().encode_hex::<String>().as_bytes());
                mac.update(self.ciphertext.encode_hex::<String>().as_bytes());
                mac.update(key.encode_hex::<String>().as_bytes());
                mac.finalize().into_bytes().to_vec()
            },
        )
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
