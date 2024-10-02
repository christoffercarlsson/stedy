use alloc::vec::Vec;

use crate::{
    base::{base16_encode, base32_encode, base64_encode},
    Encoding,
};

pub fn encode(bytes: &[u8], encoding: Encoding) -> Vec<u8> {
    match encoding {
        Encoding::Hex | Encoding::Base16 => base16_encode(bytes),
        Encoding::Base32 => base32_encode(bytes, true),
        Encoding::Base32Unpadded => base32_encode(bytes, false),
        Encoding::Base64 => base64_encode(bytes, false, true),
        Encoding::Base64Unpadded => base64_encode(bytes, false, false),
        Encoding::Base64Url => base64_encode(bytes, true, true),
        Encoding::Base64UrlUnpadded => base64_encode(bytes, true, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_encode_base16() {
        let input = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        let output = vec![
            52, 56, 54, 53, 54, 99, 54, 99, 54, 102, 50, 48, 53, 55, 54, 102, 55, 50, 54, 99, 54,
            52,
        ];
        assert_eq!(encode(&input, Encoding::Hex), output);
        assert_eq!(encode(&input, Encoding::Base16), output);
    }

    #[test]
    fn test_encode_base32() {
        let input = vec![102, 111, 111, 98, 97, 114];
        let output_padded = vec![
            77, 90, 88, 87, 54, 89, 84, 66, 79, 73, 61, 61, 61, 61, 61, 61,
        ];
        let output_unpadded = vec![77, 90, 88, 87, 54, 89, 84, 66, 79, 73];
        assert_eq!(encode(&input, Encoding::Base32), output_padded);
        assert_eq!(encode(&input, Encoding::Base32Unpadded), output_unpadded);
    }

    #[test]
    fn test_encode_base64() {
        let input = vec![
            29, 89, 252, 80, 41, 132, 67, 161, 81, 187, 159, 165, 194, 153, 63, 84,
        ];
        let output_padded = vec![
            72, 86, 110, 56, 85, 67, 109, 69, 81, 54, 70, 82, 117, 53, 43, 108, 119, 112, 107, 47,
            86, 65, 61, 61,
        ];
        let output_unpadded = vec![
            72, 86, 110, 56, 85, 67, 109, 69, 81, 54, 70, 82, 117, 53, 43, 108, 119, 112, 107, 47,
            86, 65,
        ];
        let output_url_padded = vec![
            72, 86, 110, 56, 85, 67, 109, 69, 81, 54, 70, 82, 117, 53, 45, 108, 119, 112, 107, 95,
            86, 65, 61, 61,
        ];
        let output_url_unpadded = vec![
            72, 86, 110, 56, 85, 67, 109, 69, 81, 54, 70, 82, 117, 53, 45, 108, 119, 112, 107, 95,
            86, 65,
        ];
        assert_eq!(encode(&input, Encoding::Base64), output_padded);
        assert_eq!(encode(&input, Encoding::Base64Unpadded), output_unpadded);
        assert_eq!(encode(&input, Encoding::Base64Url), output_url_padded);
        assert_eq!(
            encode(&input, Encoding::Base64UrlUnpadded),
            output_url_unpadded
        );
    }
}
