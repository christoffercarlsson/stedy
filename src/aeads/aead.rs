use crate::{
    traits::{Authenticator, ByteArray, CryptoRng, SeekableStreamCipher},
    utils::increment,
    Error,
};

pub struct Aead<C, M>
where
    C: SeekableStreamCipher,
    M: Authenticator<C>,
{
    cipher: C,
    mac: M,
}

impl<C, M> Aead<C, M>
where
    C: SeekableStreamCipher,
    M: Authenticator<C>,
{
    pub fn encrypt(
        key: &C::Key,
        nonce: &C::Nonce,
        aad: Option<&[u8]>,
        message: &mut [u8],
    ) -> Result<M::Output, Error> {
        if !M::ACCEPTS_AAD && aad.is_some() {
            return Err(Error::Misuse);
        }
        let mut aead = Self::new(key, nonce);
        aead.cipher.apply_keystream(message);
        Ok(aead.mac.tag(message, aad))
    }

    pub fn decrypt(
        key: &C::Key,
        nonce: &C::Nonce,
        aad: Option<&[u8]>,
        message: &mut [u8],
        tag: &M::Output,
    ) -> Result<(), Error> {
        if !M::ACCEPTS_AAD && aad.is_some() {
            return Err(Error::Misuse);
        }
        let mut aead = Self::new(key, nonce);
        if !aead.mac.verify(message, aad, tag) {
            return Err(Error::Decryption);
        }
        aead.cipher.apply_keystream(message);
        Ok(())
    }

    pub fn generate_key(rng: &mut impl CryptoRng) -> C::Key {
        let mut key = C::Key::new();
        rng.fill(key.as_mut());
        key
    }

    pub fn increment_nonce(nonce: &mut C::Nonce) -> Result<(), Error> {
        increment(nonce.as_mut())
    }
}

impl<C: SeekableStreamCipher, M: Authenticator<C>> Aead<C, M> {
    fn new(key: &C::Key, nonce: &C::Nonce) -> Self {
        let mut cipher = C::new(key, nonce);
        let mac = M::new(&mut cipher);
        Self { cipher, mac }
    }
}
