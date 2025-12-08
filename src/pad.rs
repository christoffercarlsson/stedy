use crate::wipe::wipe;

pub fn pad(unpadded: &mut [u8], unpadded_size: usize, block_size: usize) -> Option<usize> {
    let padded_size = unpadded_size + block_size - (unpadded_size % block_size);
    if padded_size > unpadded.len() {
        return None;
    }
    unpadded[unpadded_size] = 128;
    wipe(&mut unpadded[(unpadded_size + 1)..]);
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
        if byte == 128 {
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
        let mut bytes = [1, 2, 3, 4, 42, 42, 42, 42];
        pad(&mut bytes, 4, 8);
        assert_eq!(bytes, [1, 2, 3, 4, 128, 0, 0, 0]);
    }

    #[test]
    fn test_pad_single() {
        let mut bytes = [1, 2, 3, 4, 5, 6, 7, 0];
        pad(&mut bytes, 7, 8);
        assert_eq!(bytes, [1, 2, 3, 4, 5, 6, 7, 128]);
    }

    #[test]
    fn test_pad_block_size() {
        let mut bytes = [1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1];
        pad(&mut bytes, 8, 8);
        assert_eq!(bytes, [1, 2, 3, 4, 5, 6, 7, 8, 128, 0, 0, 0, 0, 0, 0, 0]);
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
