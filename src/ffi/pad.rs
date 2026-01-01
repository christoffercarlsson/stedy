use {
    crate::pad::{pad, unpad},
    core::slice,
};

#[no_mangle]
pub unsafe extern "C" fn stedy_pad(
    unpadded: *const u8,
    unpadded_size: usize,
    block_size: usize,
    padded: *mut u8,
    padded_size: usize,
) -> usize {
    let unpadded = slice::from_raw_parts(unpadded, unpadded_size);
    let padded = slice::from_raw_parts_mut(padded, padded_size);
    match pad(unpadded, block_size, padded) {
        Some(size) => size,
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn stedy_unpad(
    padded: *const u8,
    padded_size: usize,
    block_size: usize,
) -> usize {
    let padded = slice::from_raw_parts(padded, padded_size);
    match unpad(padded, block_size) {
        Some(size) => size,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_pad() {
        let unpadded = [1, 2, 3, 4];
        let mut padded = [42u8; 8];
        let size = unsafe {
            stedy_pad(
                unpadded.as_ptr(),
                unpadded.len(),
                8,
                padded.as_mut_ptr(),
                padded.len(),
            )
        };
        assert_eq!(size, 8);
        assert_eq!(padded, [1, 2, 3, 4, 128, 0, 0, 0]);
    }

    #[test]
    fn test_stedy_unpad() {
        let padded = [1, 2, 3, 4, 128, 0, 0, 0];
        let size = unsafe { stedy_unpad(padded.as_ptr(), 8, 8) };
        assert_eq!(size, 4);
        assert_eq!(padded[..size], [1, 2, 3, 4]);
    }
}
