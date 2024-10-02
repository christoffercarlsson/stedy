use alloc::vec::Vec;

use crate::{decode, encode, Encoding, Error};

pub fn transcode(
    bytes: &[u8],
    src_encoding: Encoding,
    target_encoding: Encoding,
) -> Result<Vec<u8>, Error> {
    let decoded = decode(bytes, src_encoding)?;
    Ok(encode(&decoded, target_encoding))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_transcode() {
        let input = vec![
            52, 56, 54, 53, 54, 99, 54, 99, 54, 102, 50, 48, 53, 55, 54, 102, 55, 50, 54, 99, 54,
            52,
        ];
        let output = vec![
            83, 71, 86, 115, 98, 71, 56, 103, 86, 50, 57, 121, 98, 71, 81,
        ];
        assert_eq!(
            transcode(&input, Encoding::Hex, Encoding::Base64UrlUnpadded).unwrap(),
            output
        );
    }
}
