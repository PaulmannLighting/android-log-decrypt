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
use std::str::FromStr;

#[derive(Debug, Eq, PartialEq)]
pub struct Cipher {
    header: Header,
    ciphertext: Vec<u8>,
}

impl Cipher {
    pub const fn new(header: Header, ciphertext: Vec<u8>) -> Self {
        Self { header, ciphertext }
    }

    pub fn validate(&self, key: &[u8]) -> anyhow::Result<()> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key())?;
        mac.update(&self.hash_data(key));
        let bytes: Vec<u8> = mac.finalize().into_bytes().into_iter().collect();
        if bytes == self.header.hmac() {
            Ok(())
        } else {
            Err(anyhow!("Invalid HMAC"))
        }
    }

    pub fn decrypt(&self, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut buf = self.ciphertext.clone();
        let cipher = Decryptor::<Aes256>::new(key.into(), self.header.iv().into());
        Ok(cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|error| anyhow!("{error}"))?
            .to_vec())
    }

    fn key(&self) -> Vec<u8> {
        hex::encode(self.header.key()).as_bytes().to_vec()
    }

    fn hash_data(&self, key: &[u8]) -> Vec<u8> {
        hex::encode(self.hash_bytes(key)).as_bytes().to_vec()
    }

    fn hash_bytes(&self, key: &[u8]) -> Vec<u8> {
        self.header
            .iv()
            .iter()
            .chain(self.ciphertext.iter())
            .chain(key.iter())
            .copied()
            .collect()
    }
}

impl FromStr for Cipher {
    type Err = anyhow::Error;

    fn from_str(ciphertext: &str) -> Result<Self, Self::Err> {
        if ciphertext.len() <= HEADER_HEX_LEN {
            Err(anyhow!("Cipher text too short: {}", ciphertext.len()))
        } else {
            Ok(Self::new(
                Header::from_str(&ciphertext[0..HEADER_HEX_LEN])?,
                hex::decode(&ciphertext[HEADER_HEX_LEN..])?,
            ))
        }
    }
}
