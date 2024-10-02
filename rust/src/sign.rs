use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::CryptoRngCore;

use crate::{
    key_pair::{get_private_key, get_public_key, set_key_pair},
    Error,
};

pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
pub const ED25519_KEY_PAIR_SIZE: usize = ED25519_PRIVATE_KEY_SIZE + ED25519_PUBLIC_KEY_SIZE;
pub const ED25519_SIGNATURE_SIZE: usize = 64;

pub type Ed25519PrivateKey = [u8; ED25519_PRIVATE_KEY_SIZE];
pub type Ed25519PublicKey = [u8; ED25519_PUBLIC_KEY_SIZE];
pub type Ed25519KeyPair = [u8; ED25519_KEY_PAIR_SIZE];
pub type Ed25519Signature = [u8; ED25519_SIGNATURE_SIZE];

pub fn ed25519_generate_key_pair<R: CryptoRngCore>(mut csprng: R) -> Ed25519KeyPair {
    let signing_key = SigningKey::generate(&mut csprng);
    let mut key_pair: Ed25519KeyPair = [0; ED25519_KEY_PAIR_SIZE];
    set_key_pair(
        &mut key_pair,
        signing_key.as_bytes(),
        signing_key.verifying_key().as_bytes(),
        ED25519_PRIVATE_KEY_SIZE,
    );
    key_pair
}

pub fn ed25519_get_private_key(key_pair: &Ed25519KeyPair) -> Ed25519PrivateKey {
    let mut private_key = [0; ED25519_PRIVATE_KEY_SIZE];
    get_private_key(&mut private_key, key_pair, ED25519_PRIVATE_KEY_SIZE);
    private_key
}

pub fn ed25519_get_public_key(key_pair: &Ed25519KeyPair) -> Ed25519PublicKey {
    let mut public_key = [0; ED25519_PUBLIC_KEY_SIZE];
    get_public_key(&mut public_key, key_pair, ED25519_PRIVATE_KEY_SIZE);
    public_key
}

pub fn ed25519_sign(key_pair: &Ed25519KeyPair, message: &[u8]) -> Result<Ed25519Signature, Error> {
    let signing_key = SigningKey::from_keypair_bytes(key_pair).or(Err(Error::SigningFailed))?;
    let signature = signing_key
        .try_sign(message)
        .or(Err(Error::SigningFailed))?;
    Ok(signature.into())
}

pub fn ed25519_verify(
    public_key: &Ed25519PublicKey,
    signature: &Ed25519Signature,
    message: &[u8],
) -> Result<(), Error> {
    let verifying_key = VerifyingKey::from_bytes(public_key).or(Err(Error::VerificationFailed))?;
    let signature = DalekSignature::from_slice(signature).or(Err(Error::VerificationFailed))?;
    verifying_key
        .verify(message, &signature)
        .or(Err(Error::VerificationFailed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ed25519_sign() {
        let message = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        let key_pair: Ed25519KeyPair = [
            187, 129, 5, 201, 47, 79, 117, 207, 153, 48, 200, 136, 139, 90, 233, 197, 234, 12, 195,
            165, 247, 82, 131, 84, 93, 59, 233, 61, 117, 254, 147, 254, 82, 97, 171, 66, 47, 97,
            89, 105, 150, 82, 88, 7, 31, 177, 30, 27, 118, 151, 80, 33, 122, 223, 215, 117, 191,
            254, 93, 244, 44, 57, 207, 226,
        ];
        let signature: Ed25519Signature = [
            120, 98, 147, 191, 39, 64, 138, 13, 210, 5, 188, 241, 245, 195, 130, 172, 212, 72, 202,
            247, 111, 18, 110, 65, 217, 45, 247, 184, 177, 186, 8, 241, 27, 210, 55, 77, 203, 164,
            177, 45, 45, 249, 249, 106, 112, 103, 249, 158, 64, 36, 99, 193, 25, 212, 59, 33, 32,
            213, 92, 178, 69, 9, 11, 15,
        ];
        assert_eq!(ed25519_sign(&key_pair, &message).unwrap(), signature);
    }

    #[test]
    fn test_ed25519_verify() {
        let public_key: Ed25519PublicKey = [
            82, 97, 171, 66, 47, 97, 89, 105, 150, 82, 88, 7, 31, 177, 30, 27, 118, 151, 80, 33,
            122, 223, 215, 117, 191, 254, 93, 244, 44, 57, 207, 226,
        ];
        let signature: Ed25519Signature = [
            120, 98, 147, 191, 39, 64, 138, 13, 210, 5, 188, 241, 245, 195, 130, 172, 212, 72, 202,
            247, 111, 18, 110, 65, 217, 45, 247, 184, 177, 186, 8, 241, 27, 210, 55, 77, 203, 164,
            177, 45, 45, 249, 249, 106, 112, 103, 249, 158, 64, 36, 99, 193, 25, 212, 59, 33, 32,
            213, 92, 178, 69, 9, 11, 15,
        ];
        let message = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        ed25519_verify(&public_key, &signature, &message).unwrap();
    }
}
