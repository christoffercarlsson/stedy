use {
    crate::api::{pad, unpad},
    core::slice,
};

#[no_mangle]
pub unsafe extern "C" fn stedy_pad(
    unpadded: *mut u8,
    unpadded_size: usize,
    block_size: usize,
) -> usize {
    let unpadded = slice::from_raw_parts_mut(unpadded, unpadded_size);
    match pad(unpadded, unpadded_size, block_size) {
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
