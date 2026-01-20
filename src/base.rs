use crate::{block::Block, wipe::wipe};

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

const BASE16_ALPHABET: &[u8; 16] = b"0123456789abcdef";
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_ALPHABET_URL: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const PADDING_BYTE: u8 = 61;

struct Base<const CHARS: usize, const BITS: usize, const GROUPS: usize> {
    alphabet: [u8; CHARS],
    offset: usize,
}

impl<const CHARS: usize, const BITS: usize, const GROUPS: usize> Base<CHARS, BITS, GROUPS> {
    fn new(alphabet: &[u8; CHARS]) -> Self {
        Self {
            alphabet: *alphabet,
            offset: 0,
        }
    }

    fn encode<'a>(
        mut self,
        padded: bool,
        decoded: &[u8],
        encoded: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        if Self::encoded_size(padded, decoded.len()) > encoded.len() {
            return None;
        }
        let mut block = Block::<BITS>::new();
        for byte in decoded {
            let digits = Self::to_binary(*byte);
            if let Some((head, tail)) = block.blocks(&digits) {
                self.encode_bits(&head, encoded);
                for chunk in tail {
                    self.encode_bits(chunk, encoded);
                }
            }
        }
        if let Some((chunk, _)) = block.remaining_block() {
            self.encode_bits(&chunk, encoded);
        }
        if padded {
            self.add_padding(encoded);
        }
        Some(&encoded[..self.offset])
    }

    fn encoded_size(padded: bool, decoded_size: usize) -> usize {
        let bits = decoded_size * 8;
        if padded {
            GROUPS * (bits / (BITS * GROUPS))
        } else {
            bits / BITS
        }
    }

    fn add_padding(&mut self, encoded: &mut [u8]) {
        let remainder = self.offset % GROUPS;
        if remainder > 0 {
            let padding_size = GROUPS - remainder;
            for _ in 0..padding_size {
                self.push(PADDING_BYTE, encoded);
            }
        }
    }

    fn encode_bits(&mut self, chunk: &[u8; BITS], encoded: &mut [u8]) {
        let index = Self::from_binary(chunk);
        let byte = self.alphabet[index as usize];
        self.push(byte, encoded);
    }

    fn push(&mut self, byte: u8, target: &mut [u8]) {
        target[self.offset] = byte;
        self.offset += 1;
    }

    fn decode<'a>(mut self, encoded: &[u8], decoded: &'a mut [u8]) -> Option<&'a [u8]> {
        let unpadded_size = Self::unpadded_size(encoded)?;
        let decoded_size = Self::decoded_size(unpadded_size);
        if decoded_size > decoded.len() {
            return None;
        }
        let mut block = Block::<8>::new();
        let mut error = 0;
        for byte in &encoded[..unpadded_size] {
            let index = self.find_index(&mut error, *byte);
            let digits = Self::to_binary(index);
            if let Some((head, _)) = block.blocks(&digits[(8 - BITS)..]) {
                let decoded_byte = Self::from_binary(&head);
                self.push(decoded_byte, decoded);
            }
        }
        if error == 0 {
            Some(&decoded[..self.offset])
        } else {
            wipe(decoded);
            None
        }
    }

    fn decoded_size(unpadded_size: usize) -> usize {
        (unpadded_size * BITS) / 8
    }

    fn unpadded_size(encoded: &[u8]) -> Option<usize> {
        let mut reached_padding = 0;
        let mut padding_size = 0;
        let mut error = 0;
        for &b in encoded {
            let is_padding = Self::is_padding(b);
            error |= reached_padding & (is_padding ^ 1);
            reached_padding |= is_padding;
            padding_size += is_padding;
        }
        let unpadded_size = encoded.len() - padding_size;
        if error == 0 {
            Some(unpadded_size)
        } else {
            None
        }
    }

    fn find_index(&self, error: &mut u8, byte: u8) -> u8 {
        let mut index = 0;
        let mut err = 1;
        for (i, &a) in self.alphabet.iter().enumerate() {
            let byte = Self::normalize(byte);
            let condition = (byte == a) as u8;
            let mask = condition.wrapping_neg();
            index = (index & !mask) | ((i as u8) & mask);
            err &= condition ^ 1;
        }
        *error |= err;
        index
    }

    fn normalize(byte: u8) -> u8 {
        let is_base16_uppercase =
            ((BITS == 4) as u8) & ((byte >= b'A') as u8) & ((byte <= b'F') as u8);
        let mask = (is_base16_uppercase.wrapping_neg()) & 32;
        byte ^ mask
    }

    fn is_padding(byte: u8) -> usize {
        let diff = (byte as usize) ^ (PADDING_BYTE as usize);
        1 ^ ((diff | diff.wrapping_neg()) >> (usize::BITS - 1))
    }

    fn from_binary(chunk: &[u8]) -> u8 {
        let mut number = 0;
        let msb = chunk.len() - 1;
        for (i, digit) in chunk.iter().enumerate() {
            number |= digit << (msb - i);
        }
        number
    }

    fn to_binary(byte: u8) -> [u8; 8] {
        let mut n = byte;
        let mut digits = [0; 8];
        for i in (0..8).rev() {
            digits[i] = n % 2;
            n /= 2;
        }
        digits
    }
}

type Base64 = Base<64, 6, 4>;
type Base32 = Base<32, 5, 8>;
type Base16 = Base<16, 4, 2>;

fn base64(url_safe: bool) -> Base64 {
    if url_safe {
        Base64::new(BASE64_ALPHABET_URL)
    } else {
        Base64::new(BASE64_ALPHABET)
    }
}

fn base32() -> Base32 {
    Base32::new(BASE32_ALPHABET)
}

fn base16() -> Base16 {
    Base16::new(BASE16_ALPHABET)
}

fn base64_encode<'a>(
    url_safe: bool,
    padded: bool,
    bytes: &[u8],
    encoded: &'a mut [u8],
) -> Option<&'a [u8]> {
    let base = base64(url_safe);
    base.encode(padded, bytes, encoded)
}

fn base64_decode<'a>(url_safe: bool, encoded: &[u8], decoded: &'a mut [u8]) -> Option<&'a [u8]> {
    let base = base64(url_safe);
    base.decode(encoded, decoded)
}

fn base32_encode<'a>(padded: bool, decoded: &[u8], encoded: &'a mut [u8]) -> Option<&'a [u8]> {
    let base = base32();
    base.encode(padded, decoded, encoded)
}

fn base32_decode<'a>(encoded: &[u8], decoded: &'a mut [u8]) -> Option<&'a [u8]> {
    let base = base32();
    base.decode(encoded, decoded)
}

fn base16_encode<'a>(decoded: &[u8], encoded: &'a mut [u8]) -> Option<&'a [u8]> {
    let base = base16();
    base.encode(false, decoded, encoded)
}

fn base16_decode<'a>(encoded: &[u8], decoded: &'a mut [u8]) -> Option<&'a [u8]> {
    let base = base16();
    base.decode(encoded, decoded)
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
