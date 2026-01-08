use {
    crate::base::{decode, encode, Encoding},
    core::slice,
};

#[no_mangle]
pub unsafe extern "C" fn stedy_encode(
    encoding: u8,
    decoded: *const u8,
    decoded_size: usize,
    encoded: *mut u8,
    encoded_max_size: usize,
) -> usize {
    let decoded = slice::from_raw_parts(decoded, decoded_size);
    let encoded = slice::from_raw_parts_mut(encoded, encoded_max_size);
    match base_encode(encoding, decoded, encoded) {
        Some(slice) => slice.len(),
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn stedy_decode(
    encoding: u8,
    encoded: *const u8,
    encoded_size: usize,
    decoded: *mut u8,
    decoded_max_size: usize,
) -> usize {
    let encoded = slice::from_raw_parts(encoded, encoded_size);
    let decoded = slice::from_raw_parts_mut(decoded, decoded_max_size);
    match base_decode(encoding, encoded, decoded) {
        Some(slice) => slice.len(),
        None => 0,
    }
}

fn get_encoding(encoding: u8) -> Option<Encoding> {
    match encoding {
        0 => Some(Encoding::Hex),
        1 => Some(Encoding::Base16),
        2 => Some(Encoding::Base32),
        3 => Some(Encoding::Base32Unpadded),
        4 => Some(Encoding::Base64),
        5 => Some(Encoding::Base64Unpadded),
        6 => Some(Encoding::Base64Url),
        7 => Some(Encoding::Base64UrlUnpadded),
        _ => None,
    }
}

fn base_encode<'a>(encoding: u8, decoded: &[u8], encoded: &'a mut [u8]) -> Option<&'a [u8]> {
    let encoding = get_encoding(encoding)?;
    encode(encoding, decoded, encoded)
}

fn base_decode<'a>(encoding: u8, encoded: &[u8], decoded: &'a mut [u8]) -> Option<&'a [u8]> {
    let encoding = get_encoding(encoding)?;
    decode(encoding, encoded, decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_encode() {
        let decoded = b"foobar";
        let mut encoded = [0u8; 8];
        let size = unsafe {
            stedy_encode(
                4,
                decoded.as_ptr(),
                decoded.len(),
                encoded.as_mut_ptr(),
                encoded.len(),
            )
        };
        assert_eq!(size, 8);
        assert_eq!(&encoded, b"Zm9vYmFy");
    }

    #[test]
    fn test_stedy_decode() {
        let encoded = b"Zm9vYmFy";
        let mut decoded = [0u8; 6];
        let size = unsafe {
            stedy_decode(
                4,
                encoded.as_ptr(),
                encoded.len(),
                decoded.as_mut_ptr(),
                decoded.len(),
            )
        };
        assert_eq!(size, 6);
        assert_eq!(&decoded, b"foobar");
    }
}
