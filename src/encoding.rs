mod base;

use crate::encoding::base::{
    base16_decode, base16_encode, base32_decode, base32_encode, base64_decode, base64_encode,
};

#[repr(u8)]
#[derive(Debug)]
pub enum Encoding {
    Hex = 0,
    Base16 = 1,
    Base32 = 2,
    Base32Unpadded = 3,
    Base64 = 4,
    Base64Unpadded = 5,
    Base64Url = 6,
    Base64UrlUnpadded = 7,
}

pub fn encode<'a>(encoding: Encoding, decoded: &[u8], encoded: &'a mut [u8]) -> Option<&'a [u8]> {
    match encoding {
        Encoding::Hex | Encoding::Base16 => base16_encode(decoded, encoded),
        Encoding::Base32 => base32_encode(true, decoded, encoded),
        Encoding::Base32Unpadded => base32_encode(false, decoded, encoded),
        Encoding::Base64 => base64_encode(false, true, decoded, encoded),
        Encoding::Base64Unpadded => base64_encode(false, false, decoded, encoded),
        Encoding::Base64Url => base64_encode(true, true, decoded, encoded),
        Encoding::Base64UrlUnpadded => base64_encode(true, false, decoded, encoded),
    }
}

pub fn decode<'a>(encoding: Encoding, encoded: &[u8], decoded: &'a mut [u8]) -> Option<&'a [u8]> {
    match encoding {
        Encoding::Hex | Encoding::Base16 => base16_decode(encoded, decoded),
        Encoding::Base32 | Encoding::Base32Unpadded => base32_decode(encoded, decoded),
        Encoding::Base64 | Encoding::Base64Unpadded => base64_decode(false, encoded, decoded),
        Encoding::Base64Url | Encoding::Base64UrlUnpadded => base64_decode(true, encoded, decoded),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://datatracker.ietf.org/doc/html/rfc4648#section-10

    #[test]
    fn test_encode_base16() {
        let decoded = b"foobar";
        let encoded = b"666f6f626172";
        let mut buffer = [0u8; 12];
        assert_eq!(
            encode(Encoding::Hex, decoded, &mut buffer).unwrap(),
            encoded
        );
        assert_eq!(
            encode(Encoding::Base16, decoded, &mut buffer).unwrap(),
            encoded
        );
    }

    #[test]
    fn test_decode_base16() {
        let encoded = b"666F6F626172";
        let decoded = b"foobar";
        let mut buffer = [0u8; 6];
        assert_eq!(
            decode(Encoding::Hex, encoded, &mut buffer).unwrap(),
            decoded
        );
        assert_eq!(
            decode(Encoding::Base16, encoded, &mut buffer).unwrap(),
            decoded
        );
    }

    #[test]
    fn test_encode_base32() {
        let decoded = b"foobar";
        let encoded_padded = b"MZXW6YTBOI======";
        let encoded_unpadded = b"MZXW6YTBOI";
        let mut buffer = [0u8; 16];
        assert_eq!(
            encode(Encoding::Base32, decoded, &mut buffer).unwrap(),
            encoded_padded
        );
        assert_eq!(
            encode(Encoding::Base32Unpadded, decoded, &mut buffer).unwrap(),
            encoded_unpadded
        );
    }

    #[test]
    fn test_decode_base32() {
        let encoded_padded = b"MZXW6YTBOI======";
        let encoded_unpadded = b"MZXW6YTBOI";
        let decoded = b"foobar";
        let mut buffer = [0u8; 6];
        assert_eq!(
            decode(Encoding::Base32, encoded_padded, &mut buffer).unwrap(),
            decoded
        );
        assert_eq!(
            decode(Encoding::Base32Unpadded, encoded_unpadded, &mut buffer).unwrap(),
            decoded
        );
    }

    #[test]
    fn test_encode_base64() {
        let decoded = b"foob";
        let encoded_padded = b"Zm9vYg==";
        let encoded_unpadded = b"Zm9vYg";
        let mut buffer = [0u8; 8];
        assert_eq!(
            encode(Encoding::Base64, decoded, &mut buffer).unwrap(),
            encoded_padded
        );
        assert_eq!(
            encode(Encoding::Base64Unpadded, decoded, &mut buffer).unwrap(),
            encoded_unpadded
        );
    }

    #[test]
    fn test_decode_base64() {
        let encoded_padded = b"Zm9vYg==";
        let encoded_unpadded = b"Zm9vYg";
        let decoded = b"foob";
        let mut buffer = [0u8; 4];
        assert_eq!(
            decode(Encoding::Base64Url, encoded_padded, &mut buffer).unwrap(),
            decoded
        );
        assert_eq!(
            decode(Encoding::Base64UrlUnpadded, encoded_unpadded, &mut buffer).unwrap(),
            decoded
        );
    }

    #[test]
    fn test_encode_base64_url() {
        let decoded = [
            29, 89, 252, 80, 41, 132, 67, 161, 81, 187, 159, 165, 194, 153, 63, 84,
        ];
        let encoded_padded = [
            72, 86, 110, 56, 85, 67, 109, 69, 81, 54, 70, 82, 117, 53, 45, 108, 119, 112, 107, 95,
            86, 65, 61, 61,
        ];
        let encoded_unpadded = [
            72, 86, 110, 56, 85, 67, 109, 69, 81, 54, 70, 82, 117, 53, 45, 108, 119, 112, 107, 95,
            86, 65,
        ];
        let mut buffer = [0u8; 24];
        assert_eq!(
            encode(Encoding::Base64Url, &decoded, &mut buffer).unwrap(),
            encoded_padded
        );
        assert_eq!(
            encode(Encoding::Base64UrlUnpadded, &decoded, &mut buffer).unwrap(),
            encoded_unpadded
        );
    }

    #[test]
    fn test_decode_base64_url() {
        let encoded_padded = [
            72, 86, 110, 56, 85, 67, 109, 69, 81, 54, 70, 82, 117, 53, 45, 108, 119, 112, 107, 95,
            86, 65, 61, 61,
        ];
        let encoded_unpadded = [
            72, 86, 110, 56, 85, 67, 109, 69, 81, 54, 70, 82, 117, 53, 45, 108, 119, 112, 107, 95,
            86, 65,
        ];
        let decoded = [
            29, 89, 252, 80, 41, 132, 67, 161, 81, 187, 159, 165, 194, 153, 63, 84,
        ];
        let mut buffer = [0u8; 16];
        assert_eq!(
            decode(Encoding::Base64Url, &encoded_padded, &mut buffer).unwrap(),
            decoded
        );
        assert_eq!(
            decode(Encoding::Base64UrlUnpadded, &encoded_unpadded, &mut buffer).unwrap(),
            decoded
        );
    }

    #[test]
    fn test_rejects_invalid() {
        let mut buffer = [0u8; 4];
        let encoded = b"Zm9???vYg==   ";
        let result = decode(Encoding::Base64, encoded, &mut buffer);
        assert!(result.is_none());
        let encoded = b"Zm9    vYg==";
        let result = decode(Encoding::Base64, encoded, &mut buffer);
        assert!(result.is_none());
        let encoded = b"   Zm9vYg==";
        let result = decode(Encoding::Base64, encoded, &mut buffer);
        assert!(result.is_none());
    }
}
