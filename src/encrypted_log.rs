mod header;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::KeyIvInit;
use aes::Aes256;
use anyhow::anyhow;
use cbc::cipher::{BlockDecryptMut, InvalidLength};
use cbc::Decryptor;
use header::{Header, HEADER_HEX_LEN};
use hex::{FromHex, ToHex};
use hmac::digest::core_api::CoreWrapper;
use hmac::{Hmac, HmacCore, Mac};
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
        Ok(self
            .cipher(key)
            .decrypt_padded_mut::<Pkcs7>(&mut self.ciphertext)
            .map_err(|error| anyhow!("{error}"))?
            .to_vec())
    }

    fn calculate_hmac(&self, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut mac = self.hmac()?;
        mac.update(self.header.iv().encode_hex::<String>().as_bytes());
        mac.update(self.ciphertext.encode_hex::<String>().as_bytes());
        mac.update(key.encode_hex::<String>().as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn hmac(&self) -> Result<CoreWrapper<HmacCore<Sha256>>, InvalidLength> {
        Hmac::<Sha256>::new_from_slice(hex::encode(self.header.key()).as_bytes())
    }

    fn cipher(&self, key: &[u8]) -> Decryptor<Aes256> {
        Decryptor::<Aes256>::new(key.into(), self.header.iv().into())
    }
}

impl FromHex for EncryptedLog {
    type Error = anyhow::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Self::try_from(hex.as_ref())
    }
}

impl TryFrom<&[u8]> for EncryptedLog {
    type Error = anyhow::Error;

    fn try_from(hex: &[u8]) -> Result<Self, Self::Error> {
        if hex.len() > HEADER_HEX_LEN {
            Ok(Self::new(
                Header::from_hex(&hex[0..HEADER_HEX_LEN])?,
                hex::decode(&hex[HEADER_HEX_LEN..])?,
            ))
        } else {
            Err(anyhow!("Hex code too short: {}", hex.len()))
        }
    }
}
