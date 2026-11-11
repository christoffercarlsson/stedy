use crate::{Error, elliptic_curves::P256 as P256Curve, key_exchange::Ecdh, traits::CryptoRng};
#[cfg(feature = "hazmat")]
use {
    crate::{
        elliptic_curves::{FieldP256With, ScalarP256, Weierstrass},
        traits::FieldArithmetic,
    },
    core::marker::PhantomData,
};

pub struct P256;

impl P256 {
    pub fn generate_key_pair(rng: &mut impl CryptoRng) -> Result<([u8; 32], [u8; 33]), Error> {
        Ecdh::<P256Curve>::generate_key_pair(rng)
    }

    pub fn public_key(private_key: &[u8; 32]) -> Result<[u8; 33], Error> {
        Ecdh::<P256Curve>::public_key(private_key)
    }

    pub fn key_exchange(private_key: &[u8; 32], public_key: &[u8; 33]) -> Result<[u8; 32], Error> {
        Ecdh::<P256Curve>::key_exchange(private_key, public_key)
    }
}

#[cfg(feature = "hazmat")]
pub struct P256With<A>(PhantomData<A>);

#[cfg(feature = "hazmat")]
impl<A> P256With<A>
where
    A: FieldArithmetic<Bytes = [u8; 32]>,
{
    pub fn generate_key_pair(rng: &mut impl CryptoRng) -> Result<([u8; 32], [u8; 33]), Error> {
        Ecdh::<Weierstrass<FieldP256With<A>, ScalarP256>>::generate_key_pair(rng)
    }

    pub fn public_key(private_key: &[u8; 32]) -> Result<[u8; 33], Error> {
        Ecdh::<Weierstrass<FieldP256With<A>, ScalarP256>>::public_key(private_key)
    }

    pub fn key_exchange(private_key: &[u8; 32], public_key: &[u8; 33]) -> Result<[u8; 32], Error> {
        Ecdh::<Weierstrass<FieldP256With<A>, ScalarP256>>::key_exchange(private_key, public_key)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{Error, csprngs::ChaCha20Rng},
        hex_literal::hex,
    };

    const ALICE_PRIVATE_KEY: [u8; 32] = [
        1, 8, 15, 22, 29, 36, 43, 50, 57, 64, 71, 78, 85, 92, 99, 106, 113, 120, 127, 134, 141,
        148, 155, 162, 169, 176, 183, 190, 197, 204, 211, 218,
    ];
    const ALICE_PUBLIC_KEY: [u8; 33] = [
        2, 235, 114, 223, 141, 151, 113, 101, 222, 128, 73, 149, 50, 162, 104, 83, 12, 214, 7, 119,
        93, 22, 14, 187, 88, 136, 50, 255, 81, 134, 151, 101, 97,
    ];
    const BOB_PRIVATE_KEY: [u8; 32] = [
        5, 18, 31, 44, 57, 70, 83, 96, 109, 122, 135, 148, 161, 174, 187, 200, 213, 226, 239, 252,
        9, 22, 35, 48, 61, 74, 87, 100, 113, 126, 139, 152,
    ];
    const BOB_PUBLIC_KEY: [u8; 33] = [
        2, 43, 63, 184, 25, 80, 184, 115, 27, 22, 252, 116, 136, 38, 89, 32, 81, 14, 136, 57, 81,
        40, 1, 55, 65, 241, 129, 217, 2, 124, 83, 221, 41,
    ];
    const SHARED_SECRET: [u8; 32] = [
        228, 122, 107, 150, 107, 142, 228, 107, 239, 63, 42, 58, 52, 184, 116, 232, 210, 108, 120,
        6, 150, 12, 239, 78, 38, 20, 118, 28, 80, 242, 37, 238,
    ];

    #[test]
    fn test_ecdh_p256_public_key() {
        assert_eq!(
            P256::public_key(&ALICE_PRIVATE_KEY).unwrap(),
            ALICE_PUBLIC_KEY
        );
        assert_eq!(P256::public_key(&BOB_PRIVATE_KEY).unwrap(), BOB_PUBLIC_KEY);
    }

    #[test]
    fn test_ecdh_p256_key_exchange() {
        let alice = P256::key_exchange(&ALICE_PRIVATE_KEY, &BOB_PUBLIC_KEY).unwrap();
        let bob = P256::key_exchange(&BOB_PRIVATE_KEY, &ALICE_PUBLIC_KEY).unwrap();
        assert_eq!(alice.as_ref(), &SHARED_SECRET);
        assert_eq!(bob.as_ref(), &SHARED_SECRET);
    }

    #[test]
    fn test_ecdh_p256_generate_key_pair() {
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let (private_key, public_key) = P256::generate_key_pair(&mut rng).unwrap();
        assert_eq!(P256::public_key(&private_key).unwrap(), public_key);
    }

    #[test]
    fn test_ecdh_p256_rejects_zero_private_key() {
        assert_eq!(P256::public_key(&[0u8; 32]), Err(Error::InvalidKey));
    }

    #[test]
    fn test_ecdh_p256_rejects_non_canonical_public_key() {
        assert_eq!(
            P256::key_exchange(
                &ALICE_PRIVATE_KEY,
                &hex!("02ffffffff00000001000000000000000000000001000000000000000000000004")
            ),
            Err(Error::InvalidKey)
        );
    }
}
