const IV_SIZE: usize = 16;
const KEY_SIZE: usize = 16;
const HMAC_SIZE: usize = 32;
pub const SIZE: usize = IV_SIZE + KEY_SIZE + HMAC_SIZE;

pub type Iv = [u8; IV_SIZE];
pub type Key = [u8; KEY_SIZE];
pub type Hmac = [u8; HMAC_SIZE];

#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    iv: Iv,
    key: Key,
    hmac: Hmac,
}

impl Header {
    #[must_use]
    pub const fn new(iv: Iv, key: Key, hmac: Hmac) -> Self {
        Self { iv, key, hmac }
    }

    #[must_use]
    pub const fn iv(&self) -> &Iv {
        &self.iv
    }

    #[must_use]
    pub const fn key(&self) -> &Key {
        &self.key
    }

    #[must_use]
    pub const fn hmac(&self) -> &Hmac {
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
