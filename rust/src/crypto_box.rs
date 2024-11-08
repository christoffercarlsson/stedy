use alloc::vec::Vec;
use core::array::TryFromSliceError;
use crypto_box::{
    aead::{generic_array::GenericArray, Aead},
    ChaChaBox, PublicKey as CryptoBoxPublicKey, SecretKey,
};
use rand_core::CryptoRngCore;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};

use crate::{get_random_bytes, Error};

pub const X25519_PRIVATE_KEY_SIZE: usize = 32;
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
pub const XCHACHA20_POLY1305_NONCE_SIZE: usize = 24;

pub type X25519PrivateKey = [u8; X25519_PRIVATE_KEY_SIZE];
pub type X25519PublicKey = [u8; X25519_PUBLIC_KEY_SIZE];
pub type XChaCha20Poly1305Nonce = [u8; XCHACHA20_POLY1305_NONCE_SIZE];

pub fn x25519_generate_key_pair<R: CryptoRngCore>(
    csprng: R,
) -> (X25519PrivateKey, X25519PublicKey) {
    let private = StaticSecret::random_from_rng(csprng);
    let public = DalekPublicKey::from(&private);
    let mut private_key: X25519PrivateKey = [0; X25519_PRIVATE_KEY_SIZE];
    let mut public_key: X25519PublicKey = [0; X25519_PUBLIC_KEY_SIZE];
    private_key.copy_from_slice(private.as_bytes());
    public_key.copy_from_slice(public.as_bytes());
    (private_key, public_key)
}

pub fn xchacha20poly1305_generate_nonce<R: CryptoRngCore>(csprng: R) -> XChaCha20Poly1305Nonce {
    let mut nonce: XChaCha20Poly1305Nonce = [0; XCHACHA20_POLY1305_NONCE_SIZE];
    get_random_bytes(csprng, &mut nonce);
    nonce
}

fn create_chachabox(
    our_private_key: &X25519PrivateKey,
    their_public_key: &X25519PublicKey,
) -> Result<ChaChaBox, TryFromSliceError> {
    let secret_key = SecretKey::from_bytes(our_private_key.clone());
    let public_key = CryptoBoxPublicKey::from_slice(their_public_key)?;
    Ok(ChaChaBox::new(&public_key, &secret_key))
}

pub fn x25519_encrypt(
    our_private_key: &X25519PrivateKey,
    their_public_key: &X25519PublicKey,
    nonce: &XChaCha20Poly1305Nonce,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    create_chachabox(our_private_key, their_public_key)
        .or(Err(Error::EncryptionFailed))?
        .encrypt(GenericArray::from_slice(nonce), plaintext)
        .or(Err(Error::EncryptionFailed))
}

pub fn x25519_decrypt(
    our_private_key: &X25519PrivateKey,
    their_public_key: &X25519PublicKey,
    nonce: &XChaCha20Poly1305Nonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    create_chachabox(our_private_key, their_public_key)
        .or(Err(Error::DecryptionFailed))?
        .decrypt(GenericArray::from_slice(nonce), ciphertext)
        .or(Err(Error::DecryptionFailed))
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use super::*;
    use alloc::vec;
    use rand::rngs::OsRng;

    #[test]
    fn test_x25519_encrypt_decrypt() {
        let message = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        let (alice_private_key, alice_public_key) = x25519_generate_key_pair(OsRng);
        let (bob_private_key, bob_public_key) = x25519_generate_key_pair(OsRng);
        let alice_nonce = xchacha20poly1305_generate_nonce(OsRng);
        let bob_nonce = xchacha20poly1305_generate_nonce(OsRng);
        let alice_ciphertext =
            x25519_encrypt(&alice_private_key, &bob_public_key, &alice_nonce, &message).unwrap();
        let bob_ciphertext =
            x25519_encrypt(&bob_private_key, &alice_public_key, &bob_nonce, &message).unwrap();
        let alice_plaintext = x25519_decrypt(
            &bob_private_key,
            &alice_public_key,
            &alice_nonce,
            &alice_ciphertext,
        )
        .unwrap();
        let bob_plaintext = x25519_decrypt(
            &alice_private_key,
            &bob_public_key,
            &bob_nonce,
            &bob_ciphertext,
        )
        .unwrap();
        assert_eq!(alice_plaintext, message);
        assert_eq!(bob_plaintext, message);
    }
}
