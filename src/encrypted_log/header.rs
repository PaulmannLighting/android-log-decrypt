use anyhow::anyhow;

const IV_SIZE: usize = 16;
const KEY_SIZE: usize = 16;
const HMAC_SIZE: usize = 32;
const SIZE: usize = IV_SIZE + KEY_SIZE + HMAC_SIZE;

#[derive(Debug, Eq, PartialEq)]
pub struct Header([u8; SIZE]);

impl Header {
    #[must_use]
    pub const fn size() -> usize {
        SIZE
    }

    #[must_use]
    pub fn iv(&self) -> &[u8] {
        &self.0[0..IV_SIZE]
    }

    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.0[IV_SIZE..IV_SIZE + KEY_SIZE]
    }

    #[must_use]
    pub fn hmac(&self) -> &[u8] {
        &self.0[IV_SIZE + KEY_SIZE..SIZE]
    }
}

impl TryFrom<&[u8]> for Header {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(<[u8; SIZE]>::try_from(
            bytes
                .get(0..SIZE)
                .ok_or_else(|| anyhow!("Too new bytes: {}", bytes.len()))?,
        )?))
    }
}
