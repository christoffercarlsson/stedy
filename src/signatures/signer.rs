use crate::{Error, traits::SignatureScheme};

pub struct Signer<'a, T>
where
    T: SignatureScheme,
{
    private_key: &'a T::PrivateKey,
}

impl<'a, T> Signer<'a, T>
where
    T: SignatureScheme,
{
    pub const fn new(private_key: &'a T::PrivateKey) -> Self {
        Self { private_key }
    }

    pub fn public_key(&self) -> Result<T::PublicKey, Error> {
        T::public_key(self.private_key)
    }

    pub fn sign(&self, message: &[u8]) -> Result<T::Signature, Error> {
        T::sign(self.private_key, message)
    }

    pub fn verify(
        message: &[u8],
        public_key: &T::PublicKey,
        signature: &T::Signature,
    ) -> Result<(), Error> {
        T::verify(message, public_key, signature)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            csprngs::ChaCha20Rng,
            signatures::{Ed25519, MlDsa44, P256},
        },
    };

    #[test]
    fn test_signer_ed25519() {
        test_signer::<Ed25519>();
    }

    #[test]
    fn test_signer_p256() {
        test_signer::<P256>();
    }

    #[test]
    fn test_signer_ml_dsa_44() {
        test_signer::<MlDsa44>();
    }

    fn test_signer<T: SignatureScheme>() {
        let mut rng = ChaCha20Rng::from(&[7u8; 96]);
        let (private_key, public_key) = T::generate_key_pair(&mut rng).unwrap();
        let signer = Signer::<T>::new(&private_key);
        let message = b"message";
        assert_eq!(signer.public_key().unwrap().as_ref(), public_key.as_ref());
        let signature = signer.sign(message).unwrap();
        Signer::<T>::verify(message, &public_key, &signature).unwrap();
    }
}
