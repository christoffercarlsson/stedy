use aes_gcm::Aes256Gcm;
use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, Payload},
    AeadCore, ChaCha20Poly1305, KeyInit,
};
use rand_core::CryptoRngCore;

use crate::Error;

pub const AES_256_GCM_NONCE_SIZE: usize = 12;
pub const AES_256_GCM_KEY_SIZE: usize = 32;
pub const AES_256_GCM_TAG_SIZE: usize = 16;
pub const CHACHA20_POLY1305_NONCE_SIZE: usize = 12;
pub const CHACHA20_POLY1305_KEY_SIZE: usize = 32;
pub const CHACHA20_POLY1305_TAG_SIZE: usize = 16;

pub type Aes256GcmNonce = [u8; AES_256_GCM_NONCE_SIZE];
pub type Aes256GcmKey = [u8; AES_256_GCM_KEY_SIZE];
pub type ChaCha20Poly1305Nonce = [u8; CHACHA20_POLY1305_NONCE_SIZE];
pub type ChaCha20Poly1305Key = [u8; CHACHA20_POLY1305_KEY_SIZE];

fn get_payload<'a>(msg: &'a [u8], aad: Option<&'a [u8]>) -> Payload<'a, 'a> {
    match aad {
        Some(aad) => Payload { msg, aad },
        None => Payload { msg, aad: &[] },
    }
}

pub fn aes_256_gcm_generate_key<R: CryptoRngCore>(csprng: R) -> Aes256GcmKey {
    let mut secret_key: Aes256GcmKey = [0; AES_256_GCM_KEY_SIZE];
    secret_key.copy_from_slice(Aes256Gcm::generate_key(csprng).as_slice());
    secret_key
}

pub fn aes_256_gcm_generate_nonce<R: CryptoRngCore>(csprng: R) -> Aes256GcmNonce {
    let mut nonce: Aes256GcmNonce = [0; AES_256_GCM_NONCE_SIZE];
    nonce.copy_from_slice(Aes256Gcm::generate_nonce(csprng).as_slice());
    nonce
}

pub fn aes_256_gcm_encrypt(
    key: &Aes256GcmKey,
    nonce: &Aes256GcmNonce,
    plaintext: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    Aes256Gcm::new(GenericArray::from_slice(key))
        .encrypt(
            GenericArray::from_slice(nonce),
            get_payload(plaintext, additional_data),
        )
        .or(Err(Error::EncryptionFailed))
}

pub fn aes_256_gcm_decrypt(
    key: &Aes256GcmKey,
    nonce: &Aes256GcmNonce,
    ciphertext: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    Aes256Gcm::new(GenericArray::from_slice(key))
        .decrypt(
            GenericArray::from_slice(nonce),
            get_payload(ciphertext, additional_data),
        )
        .or(Err(Error::DecryptionFailed))
}

pub fn chacha20poly1305_generate_key<R: CryptoRngCore>(csprng: R) -> ChaCha20Poly1305Key {
    let mut secret_key: ChaCha20Poly1305Key = [0; CHACHA20_POLY1305_KEY_SIZE];
    secret_key.copy_from_slice(ChaCha20Poly1305::generate_key(csprng).as_slice());
    secret_key
}

pub fn chacha20poly1305_generate_nonce<R: CryptoRngCore>(csprng: R) -> ChaCha20Poly1305Nonce {
    let mut nonce: ChaCha20Poly1305Nonce = [0; CHACHA20_POLY1305_NONCE_SIZE];
    nonce.copy_from_slice(ChaCha20Poly1305::generate_nonce(csprng).as_slice());
    nonce
}

pub fn chacha20poly1305_encrypt(
    key: &ChaCha20Poly1305Key,
    nonce: &ChaCha20Poly1305Nonce,
    plaintext: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    ChaCha20Poly1305::new(GenericArray::from_slice(key))
        .encrypt(
            GenericArray::from_slice(nonce),
            get_payload(plaintext, additional_data),
        )
        .or(Err(Error::EncryptionFailed))
}

pub fn chacha20poly1305_decrypt(
    key: &ChaCha20Poly1305Key,
    nonce: &ChaCha20Poly1305Nonce,
    ciphertext: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    ChaCha20Poly1305::new(GenericArray::from_slice(key))
        .decrypt(
            GenericArray::from_slice(nonce),
            get_payload(ciphertext, additional_data),
        )
        .or(Err(Error::DecryptionFailed))
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use super::*;
    use alloc::vec;
    use rand::rngs::OsRng;

    #[test]
    fn test_aes_256_gcm_encrypt_decrypt() {
        let message = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        let key = aes_256_gcm_generate_key(OsRng);
        let nonce = aes_256_gcm_generate_nonce(OsRng);
        let ciphertext = aes_256_gcm_encrypt(&key, &nonce, &message, None).unwrap();
        let plaintext = aes_256_gcm_decrypt(&key, &nonce, &ciphertext, None).unwrap();
        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_aes_256_gcm_additional_data() {
        let message = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        let data = vec![1, 2, 3];
        let key: Aes256GcmKey = [
            8, 232, 211, 161, 7, 21, 159, 203, 248, 138, 13, 110, 187, 244, 159, 22, 4, 118, 165,
            122, 127, 76, 130, 213, 97, 21, 15, 99, 176, 239, 200, 78,
        ];
        let nonce: Aes256GcmNonce = [221, 163, 154, 234, 230, 36, 36, 173, 3, 240, 149, 127];
        let ciphertext = aes_256_gcm_encrypt(&key, &nonce, &message, Some(&data)).unwrap();
        let plaintext = aes_256_gcm_decrypt(&key, &nonce, &ciphertext, Some(&data)).unwrap();
        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_chacha20poly1305_encrypt_decrypt() {
        let message = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        let key = chacha20poly1305_generate_key(OsRng);
        let nonce = chacha20poly1305_generate_nonce(OsRng);
        let ciphertext = chacha20poly1305_encrypt(&key, &nonce, &message, None).unwrap();
        let plaintext = chacha20poly1305_decrypt(&key, &nonce, &ciphertext, None).unwrap();
        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_chacha20poly1305_additional_data() {
        let message = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        let data = vec![1, 2, 3];
        let key: ChaCha20Poly1305Key = [
            8, 232, 211, 161, 7, 21, 159, 203, 248, 138, 13, 110, 187, 244, 159, 22, 4, 118, 165,
            122, 127, 76, 130, 213, 97, 21, 15, 99, 176, 239, 200, 78,
        ];
        let nonce: ChaCha20Poly1305Nonce = [221, 163, 154, 234, 230, 36, 36, 173, 3, 240, 149, 127];
        let ciphertext = chacha20poly1305_encrypt(&key, &nonce, &message, Some(&data)).unwrap();
        let plaintext = chacha20poly1305_decrypt(&key, &nonce, &ciphertext, Some(&data)).unwrap();
        assert_eq!(plaintext, message);
    }
}
