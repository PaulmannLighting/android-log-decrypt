const IV_SIZE: usize = 16;
const KEY_SIZE: usize = 16;
const HMAC_SIZE: usize = 32;
pub const SIZE: usize = IV_SIZE + KEY_SIZE + HMAC_SIZE;

#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    iv: [u8; IV_SIZE],
    key: [u8; KEY_SIZE],
    hmac: [u8; HMAC_SIZE],
}

impl Header {
    #[must_use]
    pub const fn new(iv: [u8; IV_SIZE], key: [u8; KEY_SIZE], hmac: [u8; HMAC_SIZE]) -> Self {
        Self { iv, key, hmac }
    }

    #[must_use]
    pub const fn iv(&self) -> &[u8; IV_SIZE] {
        &self.iv
    }

    #[must_use]
    pub const fn key(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }

    #[must_use]
    pub const fn hmac(&self) -> &[u8; HMAC_SIZE] {
        &self.hmac
    }
}

#[allow(clippy::unwrap_used, clippy::fallible_impl_from)]
impl From<[u8; SIZE]> for Header {
    fn from(bytes: [u8; SIZE]) -> Self {
        Self::new(
            bytes[0..IV_SIZE].try_into().unwrap(),
            bytes[IV_SIZE..IV_SIZE + KEY_SIZE].try_into().unwrap(),
            bytes[IV_SIZE + KEY_SIZE..SIZE].try_into().unwrap(),
        )
    }
}
