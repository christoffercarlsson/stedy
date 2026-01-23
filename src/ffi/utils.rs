use {
    crate::utils::{pad_to_block, pad_to_capacity, unpad, verify, wipe, xor},
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

#[no_mangle]
pub unsafe extern "C" fn stedy_verify(a: *const u8, b: *const u8, size: usize) -> bool {
    let a = slice::from_raw_parts(a, size);
    let b = slice::from_raw_parts(b, size);
    verify(a, b)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_wipe(data: *mut u8, size: usize) {
    let data = slice::from_raw_parts_mut(data, size);
    wipe(data);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_xor(x: *mut u8, x_size: usize, y: *const u8, y_size: usize) {
    let x = slice::from_raw_parts_mut(x, x_size);
    let y = slice::from_raw_parts(y, y_size);
    xor(x, y);
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

    #[test]
    fn test_stedy_verify() {
        let a = [0; 16];
        let b = [0; 16];
        let c = [1; 16];
        let verified = unsafe { stedy_verify(a.as_ptr(), b.as_ptr(), 16) };
        assert!(verified);
        let verified = unsafe { stedy_verify(a.as_ptr(), c.as_ptr(), 16) };
        assert!(!verified);
        let verified = unsafe { stedy_verify(b.as_ptr(), c.as_ptr(), 16) };
        assert!(!verified);
    }

    #[test]
    fn test_stedy_wipe() {
        let mut data = [
            80, 140, 94, 140, 50, 124, 20, 226, 225, 167, 43, 163, 78, 235, 69, 47, 55, 69, 139,
            32, 158, 214, 58, 41, 77, 153, 155, 76, 134, 103, 89, 130,
        ];
        unsafe { stedy_wipe(data.as_mut_ptr(), data.len()) };
        assert_eq!(data, [0u8; 32]);
    }

    #[test]
    fn test_stedy_xor() {
        let mut x = [0, 186, 88, 78, 141, 119, 241, 56, 159, 38, 140, 216];
        let y = [0, 129, 129, 138, 254, 243, 236, 227, 82, 207, 10, 195];
        let z = [0, 59, 217, 196, 115, 132, 29, 219, 205, 233, 134, 27];
        unsafe { stedy_xor(x.as_mut_ptr(), x.len(), y.as_ptr(), y.len()) };
        assert_eq!(x, z);
    }

    #[test]
    fn test_stedy_xor_different_sizes() {
        let mut x = [0, 186, 88, 78, 141, 119, 241, 56, 159, 38, 140, 216];
        let y = [0, 129, 129, 138, 254, 243, 236, 227];
        let z = [0, 59, 217, 196, 115, 132, 29, 219, 159, 38, 140, 216];
        unsafe { stedy_xor(x.as_mut_ptr(), x.len(), y.as_ptr(), y.len()) };
        assert_eq!(x, z);
    }
}
