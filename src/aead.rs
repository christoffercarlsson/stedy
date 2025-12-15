use crate::traits::{Csprng, Init, Mac, StreamCipher};

pub struct Aead<C: StreamCipher, M: Mac> {
    cipher: C,
    mac: M,
}

impl<C: StreamCipher, M: Mac> Aead<C, M> {
    pub fn new<F>(key: &C::Key, nonce: &C::Nonce, create_mac: F) -> Self
    where
        F: Fn(&mut C) -> M,
    {
        let mut cipher = C::new(key, nonce);
        let mac = create_mac(&mut cipher);
        Self { cipher, mac }
    }

    pub fn encrypt<F>(
        mut self,
        message: &mut [u8],
        aad: Option<&[u8]>,
        calculate_tag: F,
    ) -> M::Output
    where
        F: Fn(&mut M, &[u8], Option<&[u8]>),
    {
        self.cipher.apply_keystream(message);
        calculate_tag(&mut self.mac, message, aad);
        self.mac.finalize()
    }

    pub fn decrypt<F>(
        mut self,
        message: &mut [u8],
        tag: &M::Output,
        aad: Option<&[u8]>,
        calculate_tag: F,
    ) -> bool
    where
        F: Fn(&mut M, &[u8], Option<&[u8]>),
    {
        calculate_tag(&mut self.mac, message, aad);
        let verified = self.mac.verify(tag);
        self.cipher.apply_keystream(message);
        verified
    }

    pub fn generate_key<R: Csprng>(rng: &mut R) -> C::Key {
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
