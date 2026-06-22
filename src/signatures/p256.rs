use crate::{
    elliptic_curves::{FieldP256, ScalarP256},
    hashes::Sha256,
    signatures::Ecdsa,
};

pub type P256 = Ecdsa<FieldP256, Sha256, ScalarP256, [u8; 64]>;

#[cfg(test)]
mod tests {
    use {super::*, crate::csprngs::Rng};

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
        assert_eq!(P256::public_key(&PRIVATE_KEY), PUBLIC_KEY);
    }

    #[test]
    fn test_ecdsa_p256_sign() {
        assert_eq!(P256::sign(&PRIVATE_KEY, b"sample"), SIGNATURE_SAMPLE);
        assert_eq!(P256::sign(&PRIVATE_KEY, b"test"), SIGNATURE_TEST);
    }

    #[test]
    fn test_ecdsa_p256_verify() {
        assert!(P256::verify(b"sample", &PUBLIC_KEY, &SIGNATURE_SAMPLE));
        assert!(P256::verify(b"test", &PUBLIC_KEY, &SIGNATURE_TEST));
    }

    #[test]
    fn test_ecdsa_p256_verify_rejects_wrong_message() {
        assert!(!P256::verify(b"sample", &PUBLIC_KEY, &SIGNATURE_TEST));
        assert!(!P256::verify(b"Sample", &PUBLIC_KEY, &SIGNATURE_SAMPLE));
    }

    #[test]
    fn test_ecdsa_p256_verify_rejects_tampered_signature() {
        let mut tampered = SIGNATURE_SAMPLE;
        tampered[63] ^= 1;
        assert!(!P256::verify(b"sample", &PUBLIC_KEY, &tampered));
    }

    #[test]
    fn test_ecdsa_p256_round_trip() {
        let mut rng = Rng::from(&[7u8; 128]);
        let (private_key, public_key) = P256::generate_key_pair(&mut rng);
        let signature = P256::sign(&private_key, b"round trip message");
        assert!(P256::verify(b"round trip message", &public_key, &signature));
        assert!(!P256::verify(b"another message", &public_key, &signature));
    }
}
