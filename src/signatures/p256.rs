use crate::{
    Error,
    elliptic_curves::{FieldP256, ScalarP256},
    hashes::Sha256,
    signatures::Ecdsa,
    traits::CryptoRng,
};
#[cfg(feature = "hazmat")]
use {
    crate::{
        elliptic_curves::FieldP256With,
        traits::{FieldArithmetic, Hasher},
    },
    core::marker::PhantomData,
};

pub struct P256;

impl P256 {
    pub fn generate_key_pair(rng: &mut impl CryptoRng) -> Result<([u8; 32], [u8; 33]), Error> {
        Ecdsa::<FieldP256, Sha256, ScalarP256, [u8; 64]>::generate_key_pair(rng)
    }

    pub fn public_key(private_key: &[u8; 32]) -> Result<[u8; 33], Error> {
        Ecdsa::<FieldP256, Sha256, ScalarP256, [u8; 64]>::public_key(private_key)
    }

    pub fn sign(private_key: &[u8; 32], message: &[u8]) -> Result<[u8; 64], Error> {
        Ecdsa::<FieldP256, Sha256, ScalarP256, [u8; 64]>::sign(private_key, message)
    }

    pub fn verify(
        message: &[u8],
        public_key: &[u8; 33],
        signature: &[u8; 64],
    ) -> Result<(), Error> {
        Ecdsa::<FieldP256, Sha256, ScalarP256, [u8; 64]>::verify(message, public_key, signature)
    }
}

#[cfg(feature = "hazmat")]
pub struct P256With<A, H>(PhantomData<(A, H)>);

#[cfg(feature = "hazmat")]
impl<A, H> P256With<A, H>
where
    A: FieldArithmetic<Bytes = [u8; 32]>,
    H: Hasher,
{
    pub fn generate_key_pair(rng: &mut impl CryptoRng) -> Result<([u8; 32], [u8; 33]), Error> {
        Ecdsa::<FieldP256With<A>, H, ScalarP256, [u8; 64]>::generate_key_pair(rng)
    }

    pub fn public_key(private_key: &[u8; 32]) -> Result<[u8; 33], Error> {
        Ecdsa::<FieldP256With<A>, H, ScalarP256, [u8; 64]>::public_key(private_key)
    }

    pub fn sign(private_key: &[u8; 32], message: &[u8]) -> Result<[u8; 64], Error> {
        Ecdsa::<FieldP256With<A>, H, ScalarP256, [u8; 64]>::sign(private_key, message)
    }

    pub fn verify(
        message: &[u8],
        public_key: &[u8; 33],
        signature: &[u8; 64],
    ) -> Result<(), Error> {
        Ecdsa::<FieldP256With<A>, H, ScalarP256, [u8; 64]>::verify(message, public_key, signature)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{Error, csprngs::ChaCha20Rng},
    };

    const PRIVATE_KEY: [u8; 32] = [
        201, 175, 169, 216, 69, 186, 117, 22, 107, 92, 33, 87, 103, 177, 214, 147, 78, 80, 195,
        219, 54, 232, 155, 18, 123, 138, 98, 43, 18, 15, 103, 33,
    ];
    const PUBLIC_KEY: [u8; 33] = [
        3, 96, 254, 212, 186, 37, 90, 157, 49, 201, 97, 235, 116, 198, 53, 109, 104, 192, 73, 184,
        146, 59, 97, 250, 108, 230, 105, 98, 46, 96, 242, 159, 182,
    ];
    const SIGNATURE_SAMPLE: [u8; 64] = [
        239, 212, 139, 42, 172, 182, 168, 253, 17, 64, 221, 156, 212, 94, 129, 214, 157, 44, 135,
        123, 86, 170, 249, 145, 195, 77, 14, 168, 78, 175, 55, 22, 247, 203, 28, 148, 45, 101, 124,
        65, 212, 54, 199, 161, 182, 226, 159, 101, 243, 233, 0, 219, 185, 175, 244, 6, 77, 196,
        171, 47, 132, 58, 205, 168,
    ];
    const SIGNATURE_TEST: [u8; 64] = [
        241, 171, 176, 35, 81, 131, 81, 205, 113, 216, 129, 86, 123, 30, 166, 99, 237, 62, 252,
        246, 197, 19, 43, 53, 79, 40, 211, 176, 183, 211, 131, 103, 1, 159, 65, 19, 116, 42, 43,
        20, 189, 37, 146, 107, 73, 198, 73, 21, 95, 38, 126, 96, 211, 129, 75, 76, 12, 200, 66, 80,
        228, 111, 0, 131,
    ];

    #[test]
    fn test_ecdsa_p256_public_key() {
        assert_eq!(P256::public_key(&PRIVATE_KEY), Ok(PUBLIC_KEY));
        assert_eq!(P256::public_key(&[0u8; 32]), Err(Error::InvalidKey));
    }

    #[test]
    fn test_ecdsa_p256_sign() {
        assert_eq!(P256::sign(&PRIVATE_KEY, b"sample"), Ok(SIGNATURE_SAMPLE));
        assert_eq!(P256::sign(&PRIVATE_KEY, b"test"), Ok(SIGNATURE_TEST));
    }

    #[test]
    fn test_ecdsa_p256_verify() {
        P256::verify(b"sample", &PUBLIC_KEY, &SIGNATURE_SAMPLE).unwrap();
        P256::verify(b"test", &PUBLIC_KEY, &SIGNATURE_TEST).unwrap();
    }

    #[test]
    fn test_ecdsa_p256_round_trip() {
        let mut rng = ChaCha20Rng::from(&[7u8; 96]);
        let (private_key, public_key) = P256::generate_key_pair(&mut rng).unwrap();
        let signature = P256::sign(&private_key, b"round trip message").unwrap();
        P256::verify(b"round trip message", &public_key, &signature).unwrap();
        assert_eq!(
            P256::verify(b"another message", &public_key, &signature),
            Err(Error::Verification)
        );
    }
}
