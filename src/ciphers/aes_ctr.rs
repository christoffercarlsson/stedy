use crate::{Error, ciphers::AesCtr};

pub struct Aes128Ctr(AesCtr<16>);

impl Aes128Ctr {
    pub const fn is_accelerated() -> bool {
        AesCtr::<16>::is_accelerated()
    }

    pub fn new(key: &[u8; 16], nonce: &[u8; 12]) -> Self {
        Self(AesCtr::new(key, nonce))
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.0.apply_keystream(data)
    }

    pub fn seek(&mut self, counter: u32) {
        self.0.seek(counter);
    }
}

pub struct Aes256Ctr(AesCtr<32>);

impl Aes256Ctr {
    pub const fn is_accelerated() -> bool {
        AesCtr::<32>::is_accelerated()
    }

    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        Self(AesCtr::new(key, nonce))
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.0.apply_keystream(data)
    }

    pub fn seek(&mut self, counter: u32) {
        self.0.seek(counter);
    }
}
