use crate::{elliptic_curves::P521 as P521Curve, key_exchange::Ecdh};

pub type P521 = Ecdh<P521Curve>;

#[cfg(test)]
mod tests {
    use {super::*, crate::csprngs::Rng};

    const ALICE_PRIVATE_KEY: [u8; 66] = [
        1, 8, 15, 22, 29, 36, 43, 50, 57, 64, 71, 78, 85, 92, 99, 106, 113, 120, 127, 134, 141,
        148, 155, 162, 169, 176, 183, 190, 197, 204, 211, 218, 225, 232, 239, 246, 253, 4, 11, 18,
        25, 32, 39, 46, 53, 60, 67, 74, 81, 88, 95, 102, 109, 116, 123, 130, 137, 144, 151, 158,
        165, 172, 179, 186, 193, 200,
    ];
    const ALICE_PUBLIC_KEY: [u8; 67] = [
        3, 1, 163, 54, 236, 52, 228, 171, 246, 215, 120, 211, 100, 90, 7, 198, 35, 165, 9, 29, 25,
        117, 70, 29, 219, 227, 215, 72, 235, 93, 238, 139, 13, 86, 226, 252, 228, 86, 222, 200,
        193, 126, 4, 221, 31, 73, 56, 177, 58, 2, 176, 152, 32, 87, 99, 196, 135, 105, 125, 110,
        253, 47, 42, 207, 100, 56, 224,
    ];
    const BOB_PRIVATE_KEY: [u8; 66] = [
        1, 18, 31, 44, 57, 70, 83, 96, 109, 122, 135, 148, 161, 174, 187, 200, 213, 226, 239, 252,
        9, 22, 35, 48, 61, 74, 87, 100, 113, 126, 139, 152, 165, 190, 28, 191, 202, 223, 116, 160,
        224, 67, 39, 156, 62, 188, 109, 85, 41, 226, 24, 49, 22, 69, 176, 152, 78, 141, 128, 36,
        162, 225, 8, 199, 125, 64,
    ];
    const BOB_PUBLIC_KEY: [u8; 67] = [
        2, 0, 98, 233, 93, 172, 157, 163, 15, 37, 122, 17, 160, 81, 119, 61, 20, 210, 170, 191,
        242, 219, 203, 152, 203, 166, 4, 165, 150, 161, 216, 31, 153, 18, 62, 15, 100, 141, 84, 47,
        32, 246, 39, 66, 229, 19, 199, 143, 26, 62, 78, 135, 190, 167, 198, 240, 76, 125, 210, 49,
        71, 84, 145, 103, 62, 111, 222,
    ];
    const SHARED_SECRET: [u8; 67] = [
        3, 0, 216, 144, 204, 254, 228, 166, 235, 7, 156, 185, 213, 88, 3, 67, 195, 225, 186, 132,
        174, 90, 126, 90, 222, 241, 134, 206, 229, 173, 125, 113, 28, 48, 124, 163, 214, 126, 145,
        235, 189, 240, 108, 37, 187, 35, 152, 150, 194, 131, 59, 115, 21, 11, 202, 57, 108, 220,
        79, 72, 122, 111, 158, 126, 227, 188, 200,
    ];

    #[test]
    fn test_ecdh_p521_public_key() {
        assert_eq!(
            P521::public_key(&ALICE_PRIVATE_KEY).unwrap(),
            ALICE_PUBLIC_KEY
        );
        assert_eq!(P521::public_key(&BOB_PRIVATE_KEY).unwrap(), BOB_PUBLIC_KEY);
    }

    #[test]
    fn test_ecdh_p521_key_exchange() {
        let alice = P521::key_exchange(&ALICE_PRIVATE_KEY, &BOB_PUBLIC_KEY).unwrap();
        let bob = P521::key_exchange(&BOB_PRIVATE_KEY, &ALICE_PUBLIC_KEY).unwrap();
        assert_eq!(alice, SHARED_SECRET);
        assert_eq!(bob, SHARED_SECRET);
    }

    #[test]
    fn test_ecdh_p521_generate_key_pair() {
        let mut rng = Rng::from(&[0u8; 128]);
        let (private_key, public_key) = P521::generate_key_pair(&mut rng);
        assert_eq!(P521::public_key(&private_key).unwrap(), public_key);
    }

    #[test]
    fn test_ecdh_p521_rejects_zero_private_key() {
        assert!(P521::public_key(&[0u8; 66]).is_none());
    }
}
