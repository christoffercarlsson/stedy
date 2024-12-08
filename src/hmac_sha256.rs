use crate::{verify::verify, xor, Error, Sha256};

pub struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0; 64];
        let ipad = [54; 64];
        let opad = [92; 64];
        if key.len() > 64 {
            let mut hasher = Sha256::new();
            hasher.update(key);
            let key_digest = hasher.finalize();
            k[..32].copy_from_slice(&key_digest);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut inner_key = [0; 64];
        let mut outer_key = [0; 64];
        xor(&k, &ipad, &mut inner_key);
        xor(&k, &opad, &mut outer_key);
        let mut inner = Sha256::new();
        let mut outer = Sha256::new();
        inner.update(&inner_key);
        outer.update(&outer_key);
        Self { inner, outer }
    }

    pub fn update(&mut self, message: &[u8]) {
        self.inner.update(message);
    }

    pub fn finalize_into(mut self, code: &mut [u8; 32]) {
        let digest = self.inner.finalize();
        self.outer.update(&digest);
        self.outer.finalize_into(code);
    }

    pub fn finalize(self) -> [u8; 32] {
        let mut code = [0; 32];
        self.finalize_into(&mut code);
        code
    }

    pub fn verify(self, code: &[u8; 32]) -> Result<(), Error> {
        verify(code, &self.finalize())
    }
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut hmac = HmacSha256::new(key);
    hmac.update(message);
    hmac.finalize()
}

pub fn hmac_sha256_verify(key: &[u8], message: &[u8], code: &[u8; 32]) -> Result<(), Error> {
    let mut hmac = HmacSha256::new(key);
    hmac.update(message);
    hmac.verify(code)
}
