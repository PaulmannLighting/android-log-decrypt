use anyhow::anyhow;
use std::str::FromStr;

pub const HEADER_HEX_LEN: usize = 128;

#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    iv: [u8; 16],
    key: [u8; 16],
    hmac: [u8; 32],
}

impl Header {
    pub const fn new(iv: [u8; 16], ke: [u8; 16], hmac: [u8; 32]) -> Self {
        Self { iv, key: ke, hmac }
    }

    pub const fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    pub const fn key(&self) -> &[u8; 16] {
        &self.key
    }

    pub const fn hmac(&self) -> &[u8; 32] {
        &self.hmac
    }
}

impl FromStr for Header {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == HEADER_HEX_LEN {
            Ok(Self::new(
                hex::decode(&s[0..32])?
                    .try_into()
                    .map_err(|_| anyhow!("IV out of bounds"))?,
                hex::decode(&s[32..64])?
                    .try_into()
                    .map_err(|_| anyhow!("Key out of bounds"))?,
                hex::decode(&s[64..128])?
                    .try_into()
                    .map_err(|_| anyhow!("HMAC out of bounds"))?,
            ))
        } else {
            Err(anyhow!("Invalid header size."))
        }
    }
}
