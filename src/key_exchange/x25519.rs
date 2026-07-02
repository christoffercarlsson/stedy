use crate::{elliptic_curves::Curve25519, key_exchange::Ecdh};

pub type X25519 = Ecdh<Curve25519>;

#[cfg(test)]
mod tests {
    use {super::*, crate::csprngs::Rng, hex_literal::hex};

    #[test]
    fn test_x25519_generate_key_pair() {
        let mut rng = Rng::from(&[0u8; 128]);
        let (private_key, public_key) = X25519::generate_key_pair(&mut rng);
        assert_eq!(
            private_key,
            [
                89, 151, 243, 239, 17, 196, 251, 133, 30, 56, 89, 220, 74, 144, 209, 105, 150, 125,
                139, 44, 132, 127, 191, 13, 64, 39, 240, 246, 10, 240, 124, 104
            ]
        );
        assert_eq!(
            public_key,
            [
                106, 137, 242, 0, 140, 36, 185, 25, 173, 143, 27, 126, 10, 55, 89, 147, 228, 193,
                170, 248, 174, 227, 222, 96, 40, 226, 119, 130, 91, 188, 104, 116
            ]
        );
    }

    #[test]
    fn test_x25519() {
        let alice_private_key = [
            119, 7, 109, 10, 115, 24, 165, 125, 60, 22, 193, 114, 81, 178, 102, 69, 223, 76, 47,
            135, 235, 192, 153, 42, 177, 119, 251, 165, 29, 185, 44, 42,
        ];
        let alice_public_key = [
            133, 32, 240, 9, 137, 48, 167, 84, 116, 139, 125, 220, 180, 62, 247, 90, 13, 191, 58,
            13, 38, 56, 26, 244, 235, 164, 169, 142, 170, 155, 78, 106,
        ];
        let bob_private_key = [
            93, 171, 8, 126, 98, 74, 138, 75, 121, 225, 127, 139, 131, 128, 14, 230, 111, 59, 177,
            41, 38, 24, 182, 253, 28, 47, 139, 39, 255, 136, 224, 235,
        ];
        let bob_public_key = [
            222, 158, 219, 125, 123, 125, 193, 180, 211, 91, 97, 194, 236, 228, 53, 55, 63, 131,
            67, 200, 91, 120, 103, 77, 173, 252, 126, 20, 111, 136, 43, 79,
        ];
        let shared_secret = [
            74, 93, 157, 91, 164, 206, 45, 225, 114, 142, 59, 244, 128, 53, 15, 37, 224, 126, 33,
            201, 71, 209, 158, 51, 118, 240, 155, 60, 30, 22, 23, 66,
        ];
        let public_key = X25519::public_key(&alice_private_key).unwrap();
        assert_eq!(public_key, alice_public_key);
        let public_key = X25519::public_key(&bob_private_key).unwrap();
        assert_eq!(public_key, bob_public_key);
        let secret = X25519::key_exchange(&alice_private_key, &bob_public_key).unwrap();
        assert_eq!(secret, shared_secret);
        let secret = X25519::key_exchange(&bob_private_key, &alice_public_key).unwrap();
        assert_eq!(secret, shared_secret);
    }

    // https://datatracker.ietf.org/doc/html/rfc7748#section-5.2

    #[test]
    fn test_scalar_mult_tc1() {
        let k = hex!("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex!("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let result = X25519::key_exchange(&k, &u).unwrap();
        assert_eq!(
            result,
            hex!("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );
    }

    #[test]
    fn test_scalar_mult_tc2() {
        let k = hex!("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = hex!("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let result = X25519::key_exchange(&k, &u).unwrap();
        assert_eq!(
            result,
            hex!("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        );
    }

    #[test]
    fn test_x25519_iter() {
        let k = hex!("0900000000000000000000000000000000000000000000000000000000000000");
        let u = hex!("0900000000000000000000000000000000000000000000000000000000000000");
        let result = X25519::key_exchange(&k, &u).unwrap();
        assert_eq!(
            result,
            hex!("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
        );
    }

    #[test]
    fn test_x25519_iter_1k() {
        let mut k = hex!("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = hex!("0900000000000000000000000000000000000000000000000000000000000000");
        for _ in 0..1000 {
            let result = X25519::key_exchange(&k, &u).unwrap();
            u = k;
            k = result;
        }
        assert_eq!(
            k,
            hex!("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    // #[test]
    // fn test_x25519_iter_1m() {
    //     let mut k = [
    //         9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //         0, 0, 0,
    //     ];
    //     let mut u = [
    //         9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //         0, 0, 0,
    //     ];
    //     for _ in 0..1000000 {
    //         let result = X25519::key_exchange(&k, &u).unwrap();
    //         u = k;
    //         k = result;
    //     }
    //     assert_eq!(
    //         k,
    //         [
    //             124, 57, 17, 224, 171, 37, 134, 253, 134, 68, 151, 41, 126, 87, 94, 111, 59, 198,
    //             1, 192, 136, 60, 48, 223, 95, 77, 210, 210, 79, 102, 84, 36,
    //         ]
    //     );
    // }
}
