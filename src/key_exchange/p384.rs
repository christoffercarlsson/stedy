use crate::{elliptic_curves::P384 as P384Curve, key_exchange::Ecdh};

pub type P384 = Ecdh<P384Curve>;

#[cfg(test)]
mod tests {
    use {super::*, crate::csprngs::Rng};

    const ALICE_PRIVATE_KEY: [u8; 48] = [
        1, 8, 15, 22, 29, 36, 43, 50, 57, 64, 71, 78, 85, 92, 99, 106, 113, 120, 127, 134, 141,
        148, 155, 162, 169, 176, 183, 190, 197, 204, 211, 218, 225, 232, 239, 246, 253, 4, 11, 18,
        25, 32, 39, 46, 53, 60, 67, 74,
    ];
    const ALICE_PUBLIC_KEY: [u8; 49] = [
        3, 159, 27, 107, 100, 55, 209, 91, 83, 176, 4, 135, 37, 237, 250, 170, 253, 212, 9, 79, 52,
        174, 216, 1, 47, 200, 212, 16, 13, 78, 177, 183, 216, 176, 69, 138, 231, 98, 118, 23, 255,
        54, 230, 4, 180, 45, 132, 78, 154,
    ];
    const BOB_PRIVATE_KEY: [u8; 48] = [
        5, 18, 31, 44, 57, 70, 83, 96, 109, 122, 135, 148, 161, 174, 187, 200, 213, 226, 239, 252,
        9, 22, 35, 48, 61, 74, 87, 100, 113, 126, 139, 152, 165, 178, 191, 204, 217, 230, 243, 0,
        13, 26, 39, 52, 65, 78, 91, 104,
    ];
    const BOB_PUBLIC_KEY: [u8; 49] = [
        3, 59, 199, 196, 169, 116, 224, 239, 124, 81, 149, 179, 149, 241, 36, 68, 45, 78, 86, 172,
        139, 77, 146, 132, 76, 252, 185, 201, 72, 34, 59, 50, 26, 171, 166, 170, 186, 207, 52, 150,
        76, 212, 102, 232, 56, 104, 89, 167, 0,
    ];
    const SHARED_SECRET: [u8; 49] = [
        2, 178, 223, 51, 152, 60, 207, 188, 90, 145, 250, 105, 101, 203, 251, 37, 219, 97, 116,
        111, 41, 81, 1, 160, 108, 158, 147, 225, 231, 172, 24, 48, 77, 206, 222, 224, 250, 182,
        217, 114, 7, 150, 130, 34, 157, 58, 210, 170, 74,
    ];

    #[test]
    fn test_ecdh_p384_public_key() {
        assert_eq!(
            P384::public_key(&ALICE_PRIVATE_KEY).unwrap(),
            ALICE_PUBLIC_KEY
        );
        assert_eq!(P384::public_key(&BOB_PRIVATE_KEY).unwrap(), BOB_PUBLIC_KEY);
    }

    #[test]
    fn test_ecdh_p384_key_exchange() {
        let alice = P384::key_exchange(&ALICE_PRIVATE_KEY, &BOB_PUBLIC_KEY).unwrap();
        let bob = P384::key_exchange(&BOB_PRIVATE_KEY, &ALICE_PUBLIC_KEY).unwrap();
        assert_eq!(alice, SHARED_SECRET);
        assert_eq!(bob, SHARED_SECRET);
    }

    #[test]
    fn test_ecdh_p384_generate_key_pair() {
        let mut rng = Rng::from(&[0u8; 128]);
        let (private_key, public_key) = P384::generate_key_pair(&mut rng);
        assert_eq!(P384::public_key(&private_key).unwrap(), public_key);
    }

    #[test]
    fn test_ecdh_p384_rejects_zero_private_key() {
        assert!(P384::public_key(&[0u8; 48]).is_none());
    }
}
