use crate::{elliptic_curves::P256 as P256Curve, key_exchange::Ecdh};

pub type P256 = Ecdh<P256Curve>;

#[cfg(test)]
mod tests {
    use {super::*, crate::csprngs::Rng};

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
    const SHARED_SECRET: [u8; 33] = [
        3, 228, 122, 107, 150, 107, 142, 228, 107, 239, 63, 42, 58, 52, 184, 116, 232, 210, 108,
        120, 6, 150, 12, 239, 78, 38, 20, 118, 28, 80, 242, 37, 238,
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
        assert_eq!(alice, SHARED_SECRET);
        assert_eq!(bob, SHARED_SECRET);
    }

    #[test]
    fn test_ecdh_p256_generate_key_pair() {
        let mut rng = Rng::from(&[0u8; 128]);
        let (private_key, public_key) = P256::generate_key_pair(&mut rng);
        assert_eq!(P256::public_key(&private_key).unwrap(), public_key);
    }

    #[test]
    fn test_ecdh_p256_rejects_zero_private_key() {
        assert!(P256::public_key(&[0u8; 32]).is_none());
    }
}
