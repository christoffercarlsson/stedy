use crate::{elliptic_curves::Curve25519, key_exchange::Ecdh};

pub type X25519 = Ecdh<Curve25519>;

#[cfg(test)]
mod tests {
    use {super::*, crate::csprngs::ChaCha20Rng, hex_literal::hex};

    #[test]
    fn test_x25519_generate_key_pair() {
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let (private_key, public_key) = X25519::generate_key_pair(&mut rng);
        assert_eq!(
            private_key.as_ref(),
            &[
                189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102,
                238, 246, 149, 42, 27, 28, 74, 169, 187, 175, 23, 175, 195, 58, 204
            ]
        );
        assert_eq!(
            public_key,
            [
                48, 72, 76, 124, 65, 101, 69, 153, 133, 245, 18, 124, 94, 174, 138, 160, 31, 17,
                101, 148, 187, 233, 40, 245, 70, 201, 97, 223, 58, 103, 188, 68
            ]
        );
    }

    // https://datatracker.ietf.org/doc/html/rfc7748#section-6.1

    #[test]
    fn test_x25519() {
        let alice_private_key =
            hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public_key =
            hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_private_key =
            hex!("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public_key =
            hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared_secret =
            hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        let public_key = X25519::public_key(&alice_private_key).unwrap();
        assert_eq!(public_key, alice_public_key);
        let public_key = X25519::public_key(&bob_private_key).unwrap();
        assert_eq!(public_key, bob_public_key);
        let secret = X25519::key_exchange(&alice_private_key, &bob_public_key).unwrap();
        assert_eq!(secret.as_ref(), shared_secret.as_ref());
        let secret = X25519::key_exchange(&bob_private_key, &alice_public_key).unwrap();
        assert_eq!(secret.as_ref(), shared_secret.as_ref());
    }

    // https://datatracker.ietf.org/doc/html/rfc7748#section-5.2

    #[test]
    fn test_scalar_mult_tc1() {
        let k = hex!("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex!("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let result = X25519::key_exchange(&k, &u).unwrap();
        assert_eq!(
            result.as_ref(),
            &hex!("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );
    }

    #[test]
    fn test_scalar_mult_tc2() {
        let k = hex!("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = hex!("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let result = X25519::key_exchange(&k, &u).unwrap();
        assert_eq!(
            result.as_ref(),
            &hex!("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        );
    }

    #[test]
    fn test_x25519_iter() {
        let k = hex!("0900000000000000000000000000000000000000000000000000000000000000");
        let u = hex!("0900000000000000000000000000000000000000000000000000000000000000");
        let result = X25519::key_exchange(&k, &u).unwrap();
        assert_eq!(
            result.as_ref(),
            &hex!("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
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
