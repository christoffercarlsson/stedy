use {
    crate::blake2b::{blake2b384, Blake2b384},
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedyBlake2b384State {
    pub opaque: [u8; 216],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b384(
    message: *const u8,
    message_size: usize,
    digest: *mut u8,
) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = blake2b384(message);
    ptr::copy(_digest.as_ptr(), digest, 48);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b384_init(
    state: *mut StedyBlake2b384State,
    key: *const u8,
    key_size: usize,
) {
    let key = if key.is_null() || key_size == 0 {
        None
    } else {
        Some(slice::from_raw_parts(key, key_size))
    };
    let dest = state as *mut Blake2b384;
    let src = Blake2b384::new(key);
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b384_update(
    state: *mut StedyBlake2b384State,
    message: *const u8,
    message_size: usize,
) {
    let state = state as *mut Blake2b384;
    let message = slice::from_raw_parts(message, message_size);
    ptr::read(state).update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b384_final(
    state: *const StedyBlake2b384State,
    digest: *mut u8,
) {
    let state = state as *const Blake2b384;
    let digest: &mut [u8; 48] = slice::from_raw_parts_mut(digest, 48).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b384_final_verify(
    state: *const StedyBlake2b384State,
    code: *const u8,
) -> bool {
    let state = state as *const Blake2b384;
    let code: &[u8; 48] = slice::from_raw_parts(code, 48).try_into().unwrap();
    ptr::read(state).verify(code)
}
