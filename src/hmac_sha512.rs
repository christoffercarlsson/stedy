use crate::{verify::verify, xor, Error, Sha512};

pub struct HmacSha512 {
    inner: Sha512,
    outer: Sha512,
}

impl HmacSha512 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0; 128];
        let ipad = [54; 128];
        let opad = [92; 128];
        if key.len() > 128 {
            let mut hasher = Sha512::new();
            hasher.update(key);
            let key_digest = hasher.finalize();
            k[..64].copy_from_slice(&key_digest);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut inner_key = [0; 128];
        let mut outer_key = [0; 128];
        xor(&k, &ipad, &mut inner_key);
        xor(&k, &opad, &mut outer_key);
        let mut inner = Sha512::new();
        let mut outer = Sha512::new();
        inner.update(&inner_key);
        outer.update(&outer_key);
        Self { inner, outer }
    }

    pub fn update(&mut self, message: &[u8]) {
        self.inner.update(message);
    }

    pub fn finalize_into(mut self, code: &mut [u8; 64]) {
        let digest = self.inner.finalize();
        self.outer.update(&digest);
        self.outer.finalize_into(code);
    }

    pub fn finalize(self) -> [u8; 64] {
        let mut code = [0; 64];
        self.finalize_into(&mut code);
        code
    }

    pub fn verify(self, code: &[u8; 64]) -> Result<(), Error> {
        verify(code, &self.finalize())
    }
}

pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    let mut hmac = HmacSha512::new(key);
    hmac.update(message);
    hmac.finalize()
}

pub fn hmac_sha512_verify(key: &[u8], message: &[u8], code: &[u8; 64]) -> Result<(), Error> {
    let mut hmac = HmacSha512::new(key);
    hmac.update(message);
    hmac.verify(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://datatracker.ietf.org/doc/html/rfc4231

    #[test]
    fn test_hmac_sha512_tc1() {
        let key = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let message = [72, 105, 32, 84, 104, 101, 114, 101];
        let code = hmac_sha512(&key, &message);

        hmac_sha512_verify(&key, &message, &code).unwrap();

        let expected = [
            135, 170, 124, 222, 165, 239, 97, 157, 79, 240, 180, 36, 26, 29, 108, 176, 35, 121,
            244, 226, 206, 78, 194, 120, 122, 208, 179, 5, 69, 225, 124, 222, 218, 168, 51, 183,
            214, 184, 167, 2, 3, 139, 39, 78, 174, 163, 244, 228, 190, 157, 145, 78, 235, 97, 241,
            112, 46, 105, 108, 32, 58, 18, 104, 84,
        ];

        assert_eq!(code, expected);
    }

    #[test]
    fn test_hmac_sha512_tc2() {
        let key = [74, 101, 102, 101];
        let message = [
            119, 104, 97, 116, 32, 100, 111, 32, 121, 97, 32, 119, 97, 110, 116, 32, 102, 111, 114,
            32, 110, 111, 116, 104, 105, 110, 103, 63,
        ];
        let code = hmac_sha512(&key, &message);

        hmac_sha512_verify(&key, &message, &code).unwrap();

        let expected = [
            22, 75, 122, 123, 252, 248, 25, 226, 227, 149, 251, 231, 59, 86, 224, 163, 135, 189,
            100, 34, 46, 131, 31, 214, 16, 39, 12, 215, 234, 37, 5, 84, 151, 88, 191, 117, 192, 90,
            153, 74, 109, 3, 79, 101, 248, 240, 230, 253, 202, 234, 177, 163, 77, 74, 107, 75, 99,
            110, 7, 10, 56, 188, 231, 55,
        ];

        assert_eq!(code, expected);
    }

    #[test]
    fn test_hmac_sha512_tc3() {
        let key = [
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170,
        ];
        let message = [
            221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
            221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
            221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
        ];
        let code = hmac_sha512(&key, &message);

        hmac_sha512_verify(&key, &message, &code).unwrap();

        let expected = [
            250, 115, 176, 8, 157, 86, 162, 132, 239, 176, 240, 117, 108, 137, 11, 233, 177, 181,
            219, 221, 142, 232, 26, 54, 85, 248, 62, 51, 178, 39, 157, 57, 191, 62, 132, 130, 121,
            167, 34, 200, 6, 180, 133, 164, 126, 103, 200, 7, 185, 70, 163, 55, 190, 232, 148, 38,
            116, 39, 136, 89, 225, 50, 146, 251,
        ];

        assert_eq!(code, expected);
    }

    #[test]
    fn test_hmac_sha512_tc4() {
        let key = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25,
        ];
        let message = [
            205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
            205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
            205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
        ];
        let code = hmac_sha512(&key, &message);

        hmac_sha512_verify(&key, &message, &code).unwrap();

        let expected = [
            176, 186, 70, 86, 55, 69, 140, 105, 144, 229, 168, 197, 246, 29, 74, 247, 229, 118,
            217, 127, 249, 75, 135, 45, 231, 111, 128, 80, 54, 30, 227, 219, 169, 28, 165, 193, 26,
            162, 94, 180, 214, 121, 39, 92, 197, 120, 128, 99, 165, 241, 151, 65, 18, 12, 79, 45,
            226, 173, 235, 235, 16, 162, 152, 221,
        ];

        assert_eq!(code, expected);
    }

    #[test]
    fn test_hmac_sha512_tc5() {
        let key = [
            12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
        ];
        let message = [
            84, 101, 115, 116, 32, 87, 105, 116, 104, 32, 84, 114, 117, 110, 99, 97, 116, 105, 111,
            110,
        ];
        let code = hmac_sha512(&key, &message);

        hmac_sha512_verify(&key, &message, &code).unwrap();

        let expected = [
            65, 95, 173, 98, 113, 88, 10, 83, 29, 65, 121, 188, 137, 29, 135, 166,
        ];

        assert_eq!(code[..16], expected);
    }

    #[test]
    fn test_hmac_sha512_tc6() {
        let key = [
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
        ];
        let message = [
            84, 101, 115, 116, 32, 85, 115, 105, 110, 103, 32, 76, 97, 114, 103, 101, 114, 32, 84,
            104, 97, 110, 32, 66, 108, 111, 99, 107, 45, 83, 105, 122, 101, 32, 75, 101, 121, 32,
            45, 32, 72, 97, 115, 104, 32, 75, 101, 121, 32, 70, 105, 114, 115, 116,
        ];
        let code = hmac_sha512(&key, &message);

        hmac_sha512_verify(&key, &message, &code).unwrap();

        let expected = [
            128, 178, 66, 99, 199, 193, 163, 235, 183, 20, 147, 193, 221, 123, 232, 180, 155, 70,
            209, 244, 27, 74, 238, 193, 18, 27, 1, 55, 131, 248, 243, 82, 107, 86, 208, 55, 224,
            95, 37, 152, 189, 15, 210, 33, 93, 106, 30, 82, 149, 230, 79, 115, 246, 63, 10, 236,
            139, 145, 90, 152, 93, 120, 101, 152,
        ];

        assert_eq!(code, expected);
    }

    #[test]
    fn test_hmac_sha512_tc7() {
        let key = [
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
        ];
        let message = [
            84, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 32, 117, 115, 105,
            110, 103, 32, 97, 32, 108, 97, 114, 103, 101, 114, 32, 116, 104, 97, 110, 32, 98, 108,
            111, 99, 107, 45, 115, 105, 122, 101, 32, 107, 101, 121, 32, 97, 110, 100, 32, 97, 32,
            108, 97, 114, 103, 101, 114, 32, 116, 104, 97, 110, 32, 98, 108, 111, 99, 107, 45, 115,
            105, 122, 101, 32, 100, 97, 116, 97, 46, 32, 84, 104, 101, 32, 107, 101, 121, 32, 110,
            101, 101, 100, 115, 32, 116, 111, 32, 98, 101, 32, 104, 97, 115, 104, 101, 100, 32, 98,
            101, 102, 111, 114, 101, 32, 98, 101, 105, 110, 103, 32, 117, 115, 101, 100, 32, 98,
            121, 32, 116, 104, 101, 32, 72, 77, 65, 67, 32, 97, 108, 103, 111, 114, 105, 116, 104,
            109, 46,
        ];
        let code = hmac_sha512(&key, &message);

        hmac_sha512_verify(&key, &message, &code).unwrap();

        let expected = [
            227, 123, 106, 119, 93, 200, 125, 186, 164, 223, 169, 249, 110, 94, 63, 253, 222, 189,
            113, 248, 134, 114, 137, 134, 93, 245, 163, 45, 32, 205, 201, 68, 182, 2, 44, 172, 60,
            73, 130, 177, 13, 94, 235, 85, 195, 228, 222, 21, 19, 70, 118, 251, 109, 224, 68, 96,
            101, 201, 116, 64, 250, 140, 106, 88,
        ];

        assert_eq!(code, expected);
    }
}
