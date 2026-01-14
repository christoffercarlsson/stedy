use crate::wipe::wipe;

pub fn pad<'a>(unpadded: &[u8], block_size: usize, padded: &'a mut [u8]) -> Option<&'a [u8]> {
    let unpadded_size = unpadded.len();
    let padded_size = unpadded_size + block_size - (unpadded_size % block_size);
    if padded_size > padded.len() {
        return None;
    }
    padded[..unpadded_size].copy_from_slice(unpadded);
    padded[unpadded_size] = 128;
    wipe(&mut padded[(unpadded_size + 1)..padded_size]);
    Some(&padded[..padded_size])
}

pub fn unpad<'a>(padded: &'a [u8], block_size: usize) -> Option<&'a [u8]> {
    let size = calculate_unpadded_size(padded, block_size);
    if size == 0 {
        None
    } else {
        Some(&padded[..size])
    }
}

fn calculate_unpadded_size(padded: &[u8], block_size: usize) -> usize {
    let size = padded.len();
    if size == 0 || (size % block_size) > 0 {
        return 0;
    }
    let mut found_marker = 0;
    let mut position = 0;
    let mut error = 0;
    for i in (size - block_size..size).rev() {
        let byte = padded[i];
        let is_zero = is_byte(byte, 0);
        let is_marker = is_byte(byte, 128);
        error |= (found_marker ^ 1) & (is_zero ^ 1) & (is_marker ^ 1);
        position |= ((found_marker ^ 1) & is_marker) * i;
        found_marker |= is_marker;
    }
    error |= found_marker ^ 1;
    if error == 0 {
        position
    } else {
        0
    }
}

fn is_byte(byte: u8, value: u8) -> usize {
    let diff = (byte as usize) ^ (value as usize);
    1 ^ ((diff | diff.wrapping_neg()) >> (usize::BITS - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad() {
        let unpadded = [1, 2, 3, 4];
        let mut buffer = [42u8; 8];
        let padded = pad(&unpadded, 8, &mut buffer).unwrap();
        assert_eq!(padded, [1, 2, 3, 4, 128, 0, 0, 0]);
    }

    #[test]
    fn test_pad_single() {
        let unpadded = [1, 2, 3, 4, 5, 6, 7];
        let mut buffer = [1u8; 8];
        let padded = pad(&unpadded, 8, &mut buffer).unwrap();
        assert_eq!(padded, [1, 2, 3, 4, 5, 6, 7, 128]);
    }

    #[test]
    fn test_pad_block_size() {
        let unpadded = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut buffer = [1u8; 16];
        let padded = pad(&unpadded, 8, &mut buffer).unwrap();
        assert_eq!(padded, [1, 2, 3, 4, 5, 6, 7, 8, 128, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_unpad() {
        let input = [1, 2, 3, 4, 128, 0, 0, 0];
        let unpadded = unpad(&input, 8).unwrap();
        assert_eq!(unpadded, [1, 2, 3, 4]);
    }

    #[test]
    fn test_unpad_block_size() {
        let input = [1, 2, 3, 4, 5, 6, 7, 8, 128, 0, 0, 0, 0, 0, 0, 0];
        let unpadded = unpad(&input, 8).unwrap();
        assert_eq!(unpadded, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_unpad_single() {
        let input = [1, 2, 3, 4, 5, 6, 7, 128];
        let unpadded = unpad(&input, 8).unwrap();
        assert_eq!(unpadded, [1, 2, 3, 4, 5, 6, 7]);
    }
}
