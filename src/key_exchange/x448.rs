use crate::{elliptic_curves::Curve448, key_exchange::Ecdh};

pub type X448 = Ecdh<Curve448>;

#[cfg(test)]
mod tests {
    use {super::*, crate::csprngs::ChaCha20Rng, hex_literal::hex};

    #[test]
    fn test_x448_generate_key_pair() {
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let (private_key, public_key) = X448::generate_key_pair(&mut rng);
        assert_eq!(
            private_key.as_ref(),
            &[
                189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102,
                238, 246, 149, 42, 27, 28, 74, 169, 187, 175, 23, 175, 195, 58, 204, 202, 29, 227,
                98, 39, 63, 218, 245, 127, 170, 158, 94, 212, 115, 2, 22, 109, 212, 235, 42, 215,
                1, 120, 200
            ]
        );
        assert_eq!(
            public_key,
            [
                245, 13, 33, 147, 52, 255, 222, 97, 96, 40, 91, 197, 22, 239, 229, 51, 235, 49, 81,
                169, 105, 74, 180, 49, 145, 35, 172, 7, 162, 189, 229, 104, 38, 25, 254, 57, 22,
                173, 162, 230, 250, 253, 212, 93, 169, 252, 111, 23, 253, 114, 169, 98, 223, 222,
                179, 249
            ]
        );
    }

    // https://datatracker.ietf.org/doc/html/rfc7748#section-6.2

    #[test]
    fn test_x448() {
        let alice_private_key = hex!("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
        let alice_public_key = hex!("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
        let bob_private_key = hex!("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
        let bob_public_key = hex!("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
        let shared_secret = hex!("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");
        let public_key = X448::public_key(&alice_private_key).unwrap();
        assert_eq!(public_key, alice_public_key);
        let public_key = X448::public_key(&bob_private_key).unwrap();
        assert_eq!(public_key, bob_public_key);
        let secret = X448::key_exchange(&alice_private_key, &bob_public_key).unwrap();
        assert_eq!(secret.as_ref(), shared_secret.as_ref());
        let secret = X448::key_exchange(&bob_private_key, &alice_public_key).unwrap();
        assert_eq!(secret.as_ref(), shared_secret.as_ref());
    }

    // https://datatracker.ietf.org/doc/html/rfc7748#section-5.2

    #[test]
    fn test_scalar_mult_tc1() {
        let k = hex!("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
        let u = hex!("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086");
        let result = X448::key_exchange(&k, &u).unwrap();
        assert_eq!(
            result.as_ref(),
            &hex!("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f")
        );
    }

    #[test]
    fn test_scalar_mult_tc2() {
        let k = hex!("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f");
        let u = hex!("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db");
        let result = X448::key_exchange(&k, &u).unwrap();
        assert_eq!(
            result.as_ref(),
            &hex!("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d")
        );
    }
}
