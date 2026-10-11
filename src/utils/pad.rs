use crate::{utils::wipe, Error};

pub fn pad_to_capacity<'a>(unpadded: &[u8], buffer: &'a mut [u8]) -> Result<&'a [u8], Error> {
    pad(unpadded, buffer, buffer.len())
}

pub fn pad_to_block<'a>(
    unpadded: &[u8],
    buffer: &'a mut [u8],
    block_size: usize,
) -> Result<&'a [u8], Error> {
    if block_size == 0 {
        return Err(Error::Misuse);
    }
    let unpadded_size = unpadded.len();
    let padded_size = unpadded_size + block_size - (unpadded_size % block_size);
    pad(unpadded, buffer, padded_size)
}

pub fn unpad(padded: &[u8]) -> Result<&[u8], Error> {
    let mut found_marker = 0usize;
    let mut position = 0usize;
    let mut error = 0usize;
    for i in (0..padded.len()).rev() {
        let byte = padded[i];
        let is_zero = is_byte(byte, 0);
        let is_marker = is_byte(byte, 128);
        let not_found = found_marker ^ 1;
        error |= not_found & (is_zero ^ 1) & (is_marker ^ 1);
        position |= (not_found & is_marker) * i;
        found_marker |= is_marker;
    }
    error |= found_marker ^ 1;
    if error == 0 {
        Ok(&padded[..position])
    } else {
        Err(Error::Encoding)
    }
}

fn pad<'a>(unpadded: &[u8], buffer: &'a mut [u8], padded_size: usize) -> Result<&'a [u8], Error> {
    let unpadded_size = unpadded.len();
    let buffer_size = buffer.len();
    if unpadded_size >= buffer_size || padded_size > buffer_size {
        return Err(Error::Misuse);
    }
    buffer[..unpadded_size].copy_from_slice(unpadded);
    buffer[unpadded_size] = 128;
    wipe(&mut buffer[unpadded_size + 1..padded_size]);
    Ok(&buffer[..padded_size])
}

fn is_byte(a: u8, b: u8) -> usize {
    let diff = (a as usize) ^ (b as usize);
    1 ^ ((diff | diff.wrapping_neg()) >> (usize::BITS - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_to_capacity() {
        let unpadded = [1, 2, 3, 4];
        let mut buffer = [0u8; 8];
        let padded = pad_to_capacity(&unpadded, &mut buffer).unwrap();
        assert_eq!(padded, [1, 2, 3, 4, 128, 0, 0, 0]);
    }

    #[test]
    fn test_pad_to_capacity_single_byte() {
        let unpadded = [1, 2, 3, 4, 5, 6, 7];
        let mut buffer = [0u8; 8];
        let padded = pad_to_capacity(&unpadded, &mut buffer).unwrap();
        assert_eq!(padded, [1, 2, 3, 4, 5, 6, 7, 128]);
    }

    #[test]
    fn test_pad_to_capacity_too_small() {
        let unpadded = [1, 2, 3, 4];
        let mut buffer = [0u8; 4];
        let result = pad_to_capacity(&unpadded, &mut buffer);
        assert_eq!(result, Err(Error::Misuse));
    }

    #[test]
    fn test_pad_to_block() {
        let unpadded = [1, 2, 3, 4];
        let mut buffer = [0u8; 16];
        let padded = pad_to_block(&unpadded, &mut buffer, 8).unwrap();
        assert_eq!(padded, [1, 2, 3, 4, 128, 0, 0, 0]);
        assert_eq!(pad_to_block(&unpadded, &mut buffer, 0), Err(Error::Misuse));
    }

    #[test]
    fn test_pad_to_block_exact_boundary() {
        let unpadded = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut buffer = [0u8; 16];
        let padded = pad_to_block(&unpadded, &mut buffer, 8).unwrap();
        assert_eq!(padded, [1, 2, 3, 4, 5, 6, 7, 8, 128, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_pad_to_block_single_byte() {
        let unpadded = [1, 2, 3, 4, 5, 6, 7];
        let mut buffer = [0u8; 8];
        let padded = pad_to_block(&unpadded, &mut buffer, 8).unwrap();
        assert_eq!(padded, [1, 2, 3, 4, 5, 6, 7, 128]);
    }

    #[test]
    fn test_pad_to_block_too_small() {
        let unpadded = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut buffer = [0u8; 8];
        let result = pad_to_block(&unpadded, &mut buffer, 8);
        assert_eq!(result, Err(Error::Misuse));
    }

    #[test]
    fn test_unpad() {
        assert_eq!(unpad(&[1, 2, 3, 4, 128, 0, 0, 0]).unwrap(), [1, 2, 3, 4]);
        assert_eq!(
            unpad(&[1, 2, 3, 4, 5, 6, 7, 128]).unwrap(),
            [1, 2, 3, 4, 5, 6, 7]
        );
        assert_eq!(
            unpad(&[1, 2, 3, 4, 5, 6, 7, 8, 128, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn test_unpad_empty_message() {
        let padded = [128u8];
        let unpadded = unpad(&padded).unwrap();
        assert!(unpadded.is_empty());
        let padded = [128u8, 0, 0, 0];
        let unpadded = unpad(&padded).unwrap();
        assert!(unpadded.is_empty());
    }

    #[test]
    fn test_unpad_message_contains_marker() {
        assert_eq!(unpad(&[1, 128, 2, 128, 0, 0]).unwrap(), [1, 128, 2]);
        assert_eq!(unpad(&[128, 128, 0]).unwrap(), [128]);
    }

    #[test]
    fn test_unpad_message_contains_zeros() {
        assert_eq!(unpad(&[1, 0, 2, 128, 0]).unwrap(), [1, 0, 2]);
    }

    #[test]
    fn test_unpad_invalid() {
        assert_eq!(unpad(&[]), Err(Error::Encoding));
        assert_eq!(unpad(&[1, 2, 3, 4]), Err(Error::Encoding));
        assert_eq!(unpad(&[0, 0, 0, 0]), Err(Error::Encoding));
        assert_eq!(unpad(&[1, 2, 128, 5, 0, 0]), Err(Error::Encoding));
        assert_eq!(unpad(&[1, 2, 128, 0, 5, 0]), Err(Error::Encoding));
    }
}
