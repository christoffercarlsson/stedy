use alloc::vec::Vec;

use crate::{
    base::{base16_decode, base32_decode, base64_decode},
    Encoding, Error,
};

pub fn decode(bytes: &[u8], encoding: Encoding) -> Result<Vec<u8>, Error> {
    match encoding {
        Encoding::Hex | Encoding::Base16 => base16_decode(bytes),
        Encoding::Base32 | Encoding::Base32Unpadded => base32_decode(bytes),
        Encoding::Base64 | Encoding::Base64Unpadded => base64_decode(bytes, false),
        Encoding::Base64Url | Encoding::Base64UrlUnpadded => base64_decode(bytes, true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_decode_base16() {
        let input = vec![
            52, 56, 54, 53, 54, 67, 54, 67, 54, 70, 50, 48, 53, 55, 54, 70, 55, 50, 54, 67, 54, 52,
        ];
        let output = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        assert_eq!(decode(&input, Encoding::Hex).unwrap(), output);
        assert_eq!(decode(&input, Encoding::Base16).unwrap(), output);
    }

    #[test]
    fn test_decode_base32() {
        let input_padded = vec![
            77, 90, 88, 87, 54, 89, 84, 66, 79, 73, 61, 61, 61, 61, 61, 61,
        ];
        let input_unpadded = vec![77, 90, 88, 87, 54, 89, 84, 66, 79, 73];
        let output = vec![102, 111, 111, 98, 97, 114];
        assert_eq!(decode(&input_padded, Encoding::Base32).unwrap(), output);
        assert_eq!(
            decode(&input_unpadded, Encoding::Base32Unpadded).unwrap(),
            output
        );
    }

    #[test]
    fn test_decode_base64() {
        let input_padded = vec![
            72, 86, 110, 56, 85, 67, 109, 69, 81, 54, 70, 82, 117, 53, 43, 108, 119, 112, 107, 47,
            86, 65, 61, 61,
        ];
        let input_unpadded = vec![
            72, 86, 110, 56, 85, 67, 109, 69, 81, 54, 70, 82, 117, 53, 43, 108, 119, 112, 107, 47,
            86, 65,
        ];
        let input_url_padded = vec![
            72, 86, 110, 56, 85, 67, 109, 69, 81, 54, 70, 82, 117, 53, 45, 108, 119, 112, 107, 95,
            86, 65, 61, 61,
        ];
        let input_url_unpadded = vec![
            72, 86, 110, 56, 85, 67, 109, 69, 81, 54, 70, 82, 117, 53, 45, 108, 119, 112, 107, 95,
            86, 65,
        ];
        let output = vec![
            29, 89, 252, 80, 41, 132, 67, 161, 81, 187, 159, 165, 194, 153, 63, 84,
        ];
        assert_eq!(decode(&input_padded, Encoding::Base64).unwrap(), output);
        assert_eq!(
            decode(&input_unpadded, Encoding::Base64Unpadded).unwrap(),
            output
        );
        assert_eq!(
            decode(&input_url_padded, Encoding::Base64Url).unwrap(),
            output
        );
        assert_eq!(
            decode(&input_url_unpadded, Encoding::Base64UrlUnpadded).unwrap(),
            output
        );
    }
}
