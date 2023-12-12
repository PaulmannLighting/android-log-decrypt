use anyhow::anyhow;

const IV_SIZE: usize = 16;
const KEY_SIZE: usize = 16;
const HMAC_SIZE: usize = 32;
const SIZE: usize = IV_SIZE + KEY_SIZE + HMAC_SIZE;

#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    iv: [u8; IV_SIZE],
    key: [u8; KEY_SIZE],
    hmac: [u8; HMAC_SIZE],
}

impl Header {
    #[must_use]
    pub const fn size() -> usize {
        SIZE
    }

    #[must_use]
    pub const fn iv(&self) -> &[u8] {
        &self.iv
    }

    #[must_use]
    pub const fn key(&self) -> &[u8] {
        &self.key
    }

    #[must_use]
    pub const fn hmac(&self) -> &[u8] {
        &self.hmac
    }
}

impl TryFrom<&[u8]> for Header {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            iv: bytes
                .get(0..KEY_SIZE)
                .ok_or_else(|| anyhow!("Too new bytes: {}", bytes.len()))?
                .try_into()?,
            key: bytes
                .get(KEY_SIZE..IV_SIZE + KEY_SIZE)
                .ok_or_else(|| anyhow!("Too new bytes: {}", bytes.len()))?
                .try_into()?,
            hmac: bytes
                .get(IV_SIZE + KEY_SIZE..SIZE)
                .ok_or_else(|| anyhow!("Too new bytes: {}", bytes.len()))?
                .try_into()?,
        })
    }
}
