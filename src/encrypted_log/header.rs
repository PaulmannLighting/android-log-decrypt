pub const SIZE: usize = 64;

#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    iv: [u8; 16],
    key: [u8; 16],
    hmac: [u8; 32],
}

impl Header {
    pub const fn new(iv: [u8; 16], key: [u8; 16], hmac: [u8; 32]) -> Self {
        Self { iv, key, hmac }
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

impl From<[u8; SIZE]> for Header {
    fn from(bytes: [u8; SIZE]) -> Self {
        Self::new(
            bytes[0..16].try_into().unwrap_or_else(|_| unreachable!()),
            bytes[16..32].try_into().unwrap_or_else(|_| unreachable!()),
            bytes[32..64].try_into().unwrap_or_else(|_| unreachable!()),
        )
    }
}
