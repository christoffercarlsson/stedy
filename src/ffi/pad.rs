use {
    crate::pad::{pad_to_block, pad_to_capacity, unpad},
    core::slice,
};

#[no_mangle]
pub unsafe extern "C" fn stedy_pad_to_capacity(
    unpadded: *const u8,
    unpadded_size: usize,
    buffer: *mut u8,
    buffer_size: usize,
) -> usize {
    let unpadded = slice::from_raw_parts(unpadded, unpadded_size);
    let buffer = slice::from_raw_parts_mut(buffer, buffer_size);
    match pad_to_capacity(unpadded, buffer) {
        Some(padded) => padded.len(),
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn stedy_pad_to_block(
    unpadded: *const u8,
    unpadded_size: usize,
    buffer: *mut u8,
    buffer_size: usize,
    block_size: usize,
) -> usize {
    let unpadded = slice::from_raw_parts(unpadded, unpadded_size);
    let buffer = slice::from_raw_parts_mut(buffer, buffer_size);
    match pad_to_block(unpadded, buffer, block_size) {
        Some(padded) => padded.len(),
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn stedy_unpad(padded: *const u8, padded_size: usize) -> usize {
    let padded = slice::from_raw_parts(padded, padded_size);
    match unpad(padded) {
        Some(unpadded) => unpadded.len(),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_pad_to_capacity() {
        let unpadded = [1, 2, 3, 4];
        let mut buffer = [42u8; 9];
        let size = unsafe {
            stedy_pad_to_capacity(
                unpadded.as_ptr(),
                unpadded.len(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        assert_eq!(size, 9);
        assert_eq!(buffer, [1, 2, 3, 4, 128, 0, 0, 0, 0]);
    }

    #[test]
    fn test_stedy_pad_to_block() {
        let unpadded = [1, 2, 3, 4];
        let mut buffer = [42u8; 8];
        let size = unsafe {
            stedy_pad_to_block(
                unpadded.as_ptr(),
                unpadded.len(),
                buffer.as_mut_ptr(),
                buffer.len(),
                8,
            )
        };
        assert_eq!(size, 8);
        assert_eq!(buffer, [1, 2, 3, 4, 128, 0, 0, 0]);
    }

    #[test]
    fn test_stedy_unpad() {
        let padded = [1, 2, 3, 4, 128, 0, 0, 0];
        let size = unsafe { stedy_unpad(padded.as_ptr(), padded.len()) };
        assert_eq!(size, 4);
        assert_eq!(padded[..size], [1, 2, 3, 4]);
    }
}
