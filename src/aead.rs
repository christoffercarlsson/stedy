use crate::traits::{Authenticator, CryptoRng, Init, SeekableStreamCipher};

pub struct Aead<C: SeekableStreamCipher, M: Authenticator<C>> {
    cipher: C,
    mac: M,
}

impl<C: SeekableStreamCipher, M: Authenticator<C>> Aead<C, M> {
    pub fn new(key: &C::Key, nonce: &C::Nonce) -> Self {
        let mut cipher = C::new(key, nonce);
        let mac = M::new(&mut cipher);
        Self { cipher, mac }
    }

    pub fn encrypt(mut self, message: &mut [u8], aad: Option<&[u8]>) -> M::Output {
        self.cipher.apply_keystream(message);
        self.mac.tag(message, aad)
    }

    pub fn decrypt(mut self, message: &mut [u8], tag: &M::Output, aad: Option<&[u8]>) -> bool {
        if self.mac.verify(message, aad, tag) {
            self.cipher.apply_keystream(message);
            true
        } else {
            false
        }
    }

    pub fn generate_key<R: CryptoRng>(rng: &mut R) -> C::Key {
        let mut key = C::Key::new();
        rng.fill(key.as_mut());
        key
    }

    pub fn increment_nonce(nonce: &mut C::Nonce) -> bool {
        let mut carry: u16 = 1;
        for b in nonce.as_mut().iter_mut().rev() {
            let sum = (*b as u16) + carry;
            *b = sum as u8;
            carry = sum >> 8;
        }
        carry == 0
    }
}
