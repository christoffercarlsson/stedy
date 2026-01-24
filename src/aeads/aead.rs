use crate::traits::{Authenticator, ByteArray, CryptoRng, SeekableStreamCipher};

pub struct Aead<C: SeekableStreamCipher, M: Authenticator<C>> {
    cipher: C,
    mac: M,
}

impl<C: SeekableStreamCipher, M: Authenticator<C>> Aead<C, M> {
    pub fn encrypt(
        key: &C::Key,
        nonce: &C::Nonce,
        aad: Option<&[u8]>,
        message: &mut [u8],
    ) -> M::Output {
        let mut aead = Self::new(key, nonce);
        aead.cipher.apply_keystream(message);
        aead.mac.tag(message, aad)
    }

    pub fn decrypt(
        key: &C::Key,
        nonce: &C::Nonce,
        aad: Option<&[u8]>,
        message: &mut [u8],
        tag: &M::Output,
    ) -> bool {
        let mut aead = Self::new(key, nonce);
        if aead.mac.verify(message, aad, tag) {
            aead.cipher.apply_keystream(message);
            true
        } else {
            false
        }
    }

    pub fn generate_key(rng: &mut impl CryptoRng) -> C::Key {
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

impl<C: SeekableStreamCipher, M: Authenticator<C>> Aead<C, M> {
    fn new(key: &C::Key, nonce: &C::Nonce) -> Self {
        let mut cipher = C::new(key, nonce);
        let mac = M::new(&mut cipher);
        Self { cipher, mac }
    }
}
