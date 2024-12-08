use crate::{verify::verify, xor, Error, Sha512};

pub struct HmacSha512 {
    inner: Sha512,
    outer: Sha512,
}

impl HmacSha512 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0; 128];
        let ipad = [0; 128];
        let opad = [92; 128];
        if key.len() > 128 {
            let mut hasher = Sha512::new();
            hasher.update(key);
            hasher.finalize_into(&mut k[..64].try_into().unwrap());
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut inner_key = [0; 128];
        let mut outer_key = [0; 128];
        xor(&k, &ipad, &mut inner_key);
        xor(&k, &opad, &mut outer_key);
        let mut inner = Sha512::new();
        let mut outer = Sha512::new();
        inner.update(&inner_key);
        outer.update(&outer_key);
        Self { inner, outer }
    }

    pub fn update(&mut self, message: &[u8]) {
        self.inner.update(message);
    }

    pub fn finalize_into(mut self, code: &mut [u8; 64]) {
        let digest = self.inner.finalize();
        self.outer.update(&digest);
        self.outer.finalize_into(code);
    }

    pub fn finalize(self) -> [u8; 64] {
        let mut code = [0; 64];
        self.finalize_into(&mut code);
        code
    }

    pub fn verify(self, code: &[u8; 64]) -> Result<(), Error> {
        verify(code, &self.finalize())
    }
}

pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    let mut hmac = HmacSha512::new(key);
    hmac.update(message);
    hmac.finalize()
}

pub fn hmac_sha512_verify(key: &[u8], message: &[u8], code: &[u8; 64]) -> Result<(), Error> {
    let mut hmac = HmacSha512::new(key);
    hmac.update(message);
    hmac.verify(code)
}
