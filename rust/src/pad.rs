use alloc::vec::Vec;

use crate::Error;

const PADDING_BYTE: u8 = 128;

fn calculate_padded_size(unpadded: &[u8], block_size: usize) -> usize {
    let size = unpadded.len();
    size + block_size - (size % block_size)
}

pub fn pad(bytes: &mut Vec<u8>, block_size: usize) {
    let unpadded_size = bytes.len();
    let padded_size = calculate_padded_size(bytes, block_size);
    bytes.resize(padded_size, 0);
    bytes[unpadded_size] = PADDING_BYTE;
}

fn calculate_unpadded_size(padded: &[u8], block_size: usize) -> usize {
    let size = padded.len();
    if size == 0 || (size % block_size) > 0 {
        return 0;
    }
    for i in (size - block_size..size).rev() {
        let byte = padded[i];
        if byte == PADDING_BYTE {
            return i;
        }
        if byte != 0 {
            return 0;
        }
    }
    0
}

pub fn unpad(padded: &mut Vec<u8>, block_size: usize) -> Result<(), Error> {
    let size = calculate_unpadded_size(padded, block_size);
    if size == 0 {
        return Err(Error::InvalidPadding);
    }
    padded.truncate(size);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_pad() {
        let mut input = vec![1, 2, 3, 4];
        let output = vec![1, 2, 3, 4, 128, 0, 0, 0];
        pad(&mut input, 8);
        assert_eq!(input, output);
    }

    #[test]
    fn test_pad_single() {
        let mut input = vec![1, 2, 3, 4, 5, 6, 7];
        let output = vec![1, 2, 3, 4, 5, 6, 7, 128];
        pad(&mut input, 8);
        assert_eq!(input, output);
    }

    #[test]
    fn test_pad_block_size() {
        let mut input = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let output = vec![1, 2, 3, 4, 5, 6, 7, 8, 128, 0, 0, 0, 0, 0, 0, 0];
        pad(&mut input, 8);
        assert_eq!(input, output);
    }

    #[test]
    fn test_unpad() {
        let mut input = vec![1, 2, 3, 4, 128, 0, 0, 0];
        let output = vec![1, 2, 3, 4];
        unpad(&mut input, 8).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn test_unpad_block_size() {
        let mut input = vec![1, 2, 3, 4, 5, 6, 7, 8, 128, 0, 0, 0, 0, 0, 0, 0];
        let output = vec![1, 2, 3, 4, 5, 6, 7, 8];
        unpad(&mut input, 8).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn test_unpad_single() {
        let mut input = vec![1, 2, 3, 4, 5, 6, 7, 128];
        let output = vec![1, 2, 3, 4, 5, 6, 7];
        unpad(&mut input, 8).unwrap();
        assert_eq!(input, output);
    }
}
