const PADDING_BYTE: u8 = 128;

pub fn pad(unpadded: &[u8], block_size: usize, padded: &mut [u8]) -> Option<usize> {
    let unpadded_size = unpadded.len();
    let padded_size = unpadded_size + block_size - (unpadded_size % block_size);
    if padded_size > padded.len() {
        return None;
    }
    padded[..unpadded_size].copy_from_slice(unpadded);
    padded[unpadded_size] = PADDING_BYTE;
    for b in padded[(unpadded_size + 1)..].iter_mut() {
        *b = 0;
    }
    Some(padded_size)
}

pub fn unpad(padded: &[u8], block_size: usize) -> Option<usize> {
    let size = calculate_unpadded_size(padded, block_size);
    if size == 0 {
        None
    } else {
        Some(size)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad() {
        let input = [1, 2, 3, 4];
        let mut output = [42u8; 8];
        pad(&input, 8, &mut output);
        assert_eq!(output, [1, 2, 3, 4, 128, 0, 0, 0]);
    }

    #[test]
    fn test_pad_single() {
        let input = [1, 2, 3, 4, 5, 6, 7];
        let mut output = [0u8; 8];
        pad(&input, 8, &mut output);
        assert_eq!(output, [1, 2, 3, 4, 5, 6, 7, 128]);
    }

    #[test]
    fn test_pad_block_size() {
        let input = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut output = [1u8; 16];
        pad(&input, 8, &mut output);
        assert_eq!(output, [1, 2, 3, 4, 5, 6, 7, 8, 128, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_unpad() {
        let input = [1, 2, 3, 4, 128, 0, 0, 0];
        let size = unpad(&input, 8).unwrap();
        assert_eq!(input[..size], [1, 2, 3, 4]);
    }

    #[test]
    fn test_unpad_block_size() {
        let input = [1, 2, 3, 4, 5, 6, 7, 8, 128, 0, 0, 0, 0, 0, 0, 0];
        let size = unpad(&input, 8).unwrap();
        assert_eq!(input[..size], [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_unpad_single() {
        let input = [1, 2, 3, 4, 5, 6, 7, 128];
        let size = unpad(&input, 8).unwrap();
        assert_eq!(input[..size], [1, 2, 3, 4, 5, 6, 7]);
    }
}
