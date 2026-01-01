use {
    crate::blake2s::{blake2s128, Blake2s128},
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedyBlake2s128State {
    pub opaque: [u8; 112],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s128(
    message: *const u8,
    message_size: usize,
    digest: *mut u8,
) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = blake2s128(message);
    ptr::copy(_digest.as_ptr(), digest, 16);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s128_init(
    state: *mut StedyBlake2s128State,
    key: *const u8,
    key_size: usize,
) {
    let key = if key.is_null() || key_size == 0 {
        None
    } else {
        Some(slice::from_raw_parts(key, key_size))
    };
    let dest = state as *mut Blake2s128;
    let src = Blake2s128::new(key);
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s128_update(
    state: *mut StedyBlake2s128State,
    message: *const u8,
    message_size: usize,
) {
    let state = state as *mut Blake2s128;
    let message = slice::from_raw_parts(message, message_size);
    ptr::read(state).update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s128_final(
    state: *const StedyBlake2s128State,
    digest: *mut u8,
) {
    let state = state as *const Blake2s128;
    let digest: &mut [u8; 16] = slice::from_raw_parts_mut(digest, 16).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s128_final_verify(
    state: *const StedyBlake2s128State,
    code: *const u8,
) -> bool {
    let state = state as *const Blake2s128;
    let code: &[u8; 16] = slice::from_raw_parts(code, 16).try_into().unwrap();
    ptr::read(state).verify(code)
}
