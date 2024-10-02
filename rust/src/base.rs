use alloc::{borrow::ToOwned, vec, vec::Vec};

use crate::Error;

const BASE16_ALPHABET: &[u8; 16] = b"0123456789ABCDEF";
const BASE16_ALPHABET_LOWER: &[u8; 16] = b"0123456789abcdef";
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_ALPHABET_URL: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const PADDING_BYTE: u8 = 61;

fn from_binary(digits: &[u8]) -> u8 {
    let mut number = 0;
    let msb = digits.len() - 1;
    for (i, digit) in digits.iter().enumerate() {
        number |= digit << (msb - i);
    }
    number
}

fn to_binary(mut number: u8) -> [u8; 8] {
    let mut digits = [0; 8];
    for i in (0..8).rev() {
        digits[i] = number % 2;
        number /= 2;
    }
    digits
}

fn calculate_character(alphabet: &[u8], chunk_size: usize, chunk: &[u8]) -> u8 {
    let mut padded = vec![0; chunk_size];
    padded[..chunk.len()].copy_from_slice(chunk);
    let index = from_binary(&padded);
    alphabet[index as usize]
}

fn encode(bytes: &[u8], alphabet: &[u8], chunk_size: usize) -> Vec<u8> {
    let mut bitstream = Vec::new();
    for byte in bytes {
        let digits = to_binary(byte.to_owned());
        bitstream.extend_from_slice(&digits);
    }
    let mut encoded = Vec::new();
    for chunk in bitstream.chunks(chunk_size) {
        encoded.push(calculate_character(alphabet, chunk_size, chunk))
    }
    encoded
}

fn add_padding(encoded: &mut Vec<u8>, divisor: usize) {
    let size = encoded.len();
    let remainder = size % divisor;
    if remainder > 0 {
        encoded.resize(size + (divisor - remainder), PADDING_BYTE);
    }
}

pub fn base16_encode(bytes: &[u8]) -> Vec<u8> {
    encode(bytes, BASE16_ALPHABET_LOWER, 4)
}

pub fn base32_encode(bytes: &[u8], padded: bool) -> Vec<u8> {
    let mut encoded = encode(bytes, BASE32_ALPHABET, 5);
    if padded {
        add_padding(&mut encoded, 8);
    }
    encoded
}

pub fn base64_encode(bytes: &[u8], url_safe: bool, padded: bool) -> Vec<u8> {
    let alphabet = if url_safe {
        BASE64_ALPHABET_URL
    } else {
        BASE64_ALPHABET
    };
    let mut encoded = encode(bytes, alphabet, 6);
    if padded {
        add_padding(&mut encoded, 3);
    }
    encoded
}

fn decode(bytes: &[u8], alphabet: &[u8], chunk_size: usize) -> Result<Vec<u8>, Error> {
    let mut bitstream = Vec::new();
    for byte in bytes {
        if *byte == PADDING_BYTE {
            break;
        }
        if let Some(index) = alphabet.iter().position(|b| b == byte) {
            let digits = to_binary((index as u8).to_owned());
            bitstream.extend_from_slice(&digits[(8 - chunk_size)..]);
        } else {
            return Err(Error::DecodingFailed);
        }
    }
    let mut decoded = Vec::new();
    for chunk in bitstream.chunks(8) {
        if chunk.len() == 8 {
            let byte = from_binary(chunk);
            decoded.push(byte);
        }
    }
    if decoded.is_empty() {
        return Err(Error::DecodingFailed);
    }
    Ok(decoded)
}

pub fn base16_decode(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let result = decode(bytes, BASE16_ALPHABET, 4);
    if result.is_err() {
        decode(bytes, BASE16_ALPHABET_LOWER, 4)
    } else {
        result
    }
}

pub fn base32_decode(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    decode(bytes, BASE32_ALPHABET, 5)
}

pub fn base64_decode(bytes: &[u8], url_safe: bool) -> Result<Vec<u8>, Error> {
    let alphabet = if url_safe {
        BASE64_ALPHABET_URL
    } else {
        BASE64_ALPHABET
    };
    decode(bytes, alphabet, 6)
}
