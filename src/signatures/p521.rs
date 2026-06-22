use crate::{
    elliptic_curves::{FieldP521, ScalarP521},
    hashes::Sha512,
    signatures::Ecdsa,
};

pub type P521 = Ecdsa<FieldP521, Sha512, ScalarP521, [u8; 132]>;

#[cfg(test)]
mod tests {
    use {super::*, crate::csprngs::Rng};

    const PRIVATE_KEY: [u8; 66] = [
        0, 250, 208, 109, 170, 98, 186, 59, 37, 210, 251, 64, 19, 61, 167, 87, 32, 93, 230, 127,
        91, 176, 1, 143, 238, 140, 134, 225, 182, 140, 126, 117, 202, 168, 150, 235, 50, 241, 244,
        124, 112, 133, 88, 54, 166, 209, 111, 204, 20, 102, 246, 216, 251, 236, 103, 219, 137, 236,
        12, 8, 176, 233, 150, 184, 53, 56,
    ];
    const PUBLIC_KEY: [u8; 67] = [
        3, 1, 137, 69, 80, 208, 120, 89, 50, 224, 14, 170, 35, 182, 148, 242, 19, 248, 195, 18, 31,
        134, 220, 151, 160, 78, 90, 113, 103, 219, 78, 91, 205, 55, 17, 35, 212, 110, 69, 219, 107,
        93, 83, 112, 167, 242, 15, 182, 51, 21, 93, 56, 255, 161, 109, 43, 215, 97, 220, 172, 71,
        75, 154, 47, 80, 35, 164,
    ];
    const SIGNATURE_SAMPLE: [u8; 132] = [
        0, 195, 40, 250, 252, 189, 121, 221, 119, 133, 3, 112, 196, 99, 37, 217, 135, 203, 82, 85,
        105, 251, 99, 197, 211, 188, 83, 149, 14, 109, 76, 95, 23, 78, 37, 161, 238, 144, 23, 181,
        212, 80, 96, 106, 221, 21, 43, 83, 73, 49, 215, 212, 232, 69, 92, 201, 31, 155, 21, 191, 5,
        236, 54, 227, 119, 250, 0, 97, 124, 206, 124, 245, 6, 72, 6, 196, 103, 246, 120, 211, 180,
        8, 13, 111, 28, 197, 10, 242, 108, 162, 9, 65, 115, 8, 40, 27, 104, 175, 40, 38, 35, 234,
        166, 62, 91, 92, 7, 35, 216, 184, 195, 127, 240, 119, 123, 26, 32, 248, 204, 177, 220, 204,
        67, 153, 127, 30, 224, 228, 77, 164, 166, 122,
    ];
    const SIGNATURE_TEST: [u8; 132] = [
        1, 62, 153, 2, 10, 191, 92, 238, 117, 37, 209, 107, 105, 178, 41, 101, 42, 182, 189, 242,
        175, 252, 174, 243, 135, 115, 180, 183, 208, 135, 37, 241, 12, 219, 147, 72, 47, 220, 197,
        78, 220, 238, 145, 236, 164, 22, 107, 42, 124, 98, 101, 239, 12, 226, 189, 112, 81, 183,
        206, 249, 69, 186, 189, 71, 238, 109, 1, 251, 208, 1, 60, 103, 74, 167, 156, 179, 152, 73,
        82, 121, 22, 206, 48, 28, 102, 234, 124, 232, 184, 6, 130, 120, 106, 214, 15, 152, 247,
        231, 138, 25, 202, 105, 239, 245, 197, 116, 0, 227, 179, 160, 173, 102, 206, 9, 120, 33,
        77, 19, 186, 244, 233, 172, 96, 117, 47, 123, 21, 94, 45, 228, 220, 227,
    ];

    #[test]
    fn test_ecdsa_p521_public_key() {
        assert_eq!(P521::public_key(&PRIVATE_KEY), PUBLIC_KEY);
    }

    #[test]
    fn test_ecdsa_p521_sign() {
        assert_eq!(P521::sign(&PRIVATE_KEY, b"sample"), SIGNATURE_SAMPLE);
        assert_eq!(P521::sign(&PRIVATE_KEY, b"test"), SIGNATURE_TEST);
    }

    #[test]
    fn test_ecdsa_p521_verify() {
        assert!(P521::verify(b"sample", &PUBLIC_KEY, &SIGNATURE_SAMPLE));
        assert!(P521::verify(b"test", &PUBLIC_KEY, &SIGNATURE_TEST));
    }

    #[test]
    fn test_ecdsa_p521_verify_rejects_wrong_message() {
        assert!(!P521::verify(b"sample", &PUBLIC_KEY, &SIGNATURE_TEST));
        assert!(!P521::verify(b"Sample", &PUBLIC_KEY, &SIGNATURE_SAMPLE));
    }

    #[test]
    fn test_ecdsa_p521_verify_rejects_tampered_signature() {
        let mut tampered = SIGNATURE_SAMPLE;
        tampered[131] ^= 1;
        assert!(!P521::verify(b"sample", &PUBLIC_KEY, &tampered));
    }

    #[test]
    fn test_ecdsa_p521_round_trip() {
        let mut rng = Rng::from(&[7u8; 128]);
        let (private_key, public_key) = P521::generate_key_pair(&mut rng);
        let signature = P521::sign(&private_key, b"round trip message");
        assert!(P521::verify(b"round trip message", &public_key, &signature));
        assert!(!P521::verify(b"another message", &public_key, &signature));
    }
}
