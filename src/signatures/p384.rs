use crate::{
    elliptic_curves::{FieldP384, ScalarP384},
    hashes::Sha384,
    signatures::Ecdsa,
};

pub type P384 = Ecdsa<FieldP384, Sha384, ScalarP384, [u8; 96]>;

#[cfg(test)]
mod tests {
    use {super::*, crate::csprngs::Rng};

    const PRIVATE_KEY: [u8; 48] = [
        107, 157, 61, 173, 46, 27, 140, 28, 5, 177, 152, 117, 182, 101, 159, 77, 226, 60, 59, 102,
        123, 242, 151, 186, 154, 164, 119, 64, 120, 113, 55, 216, 150, 213, 114, 78, 76, 112, 168,
        37, 248, 114, 201, 234, 96, 210, 237, 245,
    ];
    const PUBLIC_KEY: [u8; 49] = [
        2, 236, 58, 78, 65, 91, 78, 25, 164, 86, 134, 24, 2, 159, 66, 127, 165, 218, 154, 139, 196,
        174, 146, 224, 46, 6, 170, 229, 40, 107, 48, 12, 100, 222, 248, 240, 234, 144, 85, 134, 96,
        100, 162, 84, 81, 84, 128, 188, 19,
    ];
    const SIGNATURE_SAMPLE: [u8; 96] = [
        148, 237, 187, 146, 165, 236, 184, 170, 212, 115, 110, 86, 198, 145, 145, 107, 63, 136, 20,
        6, 102, 206, 159, 167, 61, 100, 196, 234, 149, 173, 19, 60, 129, 166, 72, 21, 46, 68, 172,
        249, 110, 54, 221, 30, 128, 250, 190, 70, 153, 239, 74, 235, 21, 241, 120, 206, 161, 254,
        64, 219, 38, 3, 19, 143, 19, 14, 116, 10, 25, 98, 69, 38, 32, 59, 99, 81, 208, 163, 169,
        79, 163, 41, 193, 69, 120, 110, 103, 158, 123, 130, 199, 26, 56, 98, 138, 200,
    ];
    const SIGNATURE_TEST: [u8; 96] = [
        130, 3, 182, 61, 60, 133, 62, 141, 119, 34, 127, 179, 119, 188, 247, 183, 183, 114, 233,
        120, 146, 168, 15, 54, 171, 119, 93, 80, 157, 122, 95, 235, 5, 66, 167, 240, 129, 41, 152,
        218, 143, 29, 211, 202, 60, 240, 35, 219, 221, 208, 118, 4, 72, 212, 45, 138, 67, 175, 69,
        175, 131, 111, 206, 77, 232, 190, 6, 180, 133, 233, 182, 27, 130, 124, 47, 19, 23, 57, 35,
        224, 106, 115, 159, 4, 6, 73, 166, 103, 191, 59, 130, 130, 70, 186, 165, 165,
    ];

    #[test]
    fn test_ecdsa_p384_public_key() {
        assert_eq!(P384::public_key(&PRIVATE_KEY), PUBLIC_KEY);
    }

    #[test]
    fn test_ecdsa_p384_sign() {
        assert_eq!(P384::sign(&PRIVATE_KEY, b"sample"), SIGNATURE_SAMPLE);
        assert_eq!(P384::sign(&PRIVATE_KEY, b"test"), SIGNATURE_TEST);
    }

    #[test]
    fn test_ecdsa_p384_verify() {
        assert!(P384::verify(b"sample", &PUBLIC_KEY, &SIGNATURE_SAMPLE));
        assert!(P384::verify(b"test", &PUBLIC_KEY, &SIGNATURE_TEST));
    }

    #[test]
    fn test_ecdsa_p384_verify_rejects_wrong_message() {
        assert!(!P384::verify(b"sample", &PUBLIC_KEY, &SIGNATURE_TEST));
        assert!(!P384::verify(b"Sample", &PUBLIC_KEY, &SIGNATURE_SAMPLE));
    }

    #[test]
    fn test_ecdsa_p384_verify_rejects_tampered_signature() {
        let mut tampered = SIGNATURE_SAMPLE;
        tampered[95] ^= 1;
        assert!(!P384::verify(b"sample", &PUBLIC_KEY, &tampered));
    }

    #[test]
    fn test_ecdsa_p384_round_trip() {
        let mut rng = Rng::from(&[7u8; 128]);
        let (private_key, public_key) = P384::generate_key_pair(&mut rng);
        let signature = P384::sign(&private_key, b"round trip message");
        assert!(P384::verify(b"round trip message", &public_key, &signature));
        assert!(!P384::verify(b"another message", &public_key, &signature));
    }
}
