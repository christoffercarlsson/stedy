use {
    crate::blake2b::{blake2b160, Blake2b160},
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedyBlake2b160State {
    pub opaque: [u8; 216],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b160(
    message: *const u8,
    message_size: usize,
    digest: *mut u8,
) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = blake2b160(message);
    ptr::copy(_digest.as_ptr(), digest, 20);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b160_init(
    state: *mut StedyBlake2b160State,
    key: *const u8,
    key_size: usize,
) {
    let key = if key.is_null() || key_size == 0 {
        None
    } else {
        Some(slice::from_raw_parts(key, key_size))
    };
    let dest = state as *mut Blake2b160;
    let src = Blake2b160::new(key);
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b160_update(
    state: *mut StedyBlake2b160State,
    message: *const u8,
    message_size: usize,
) {
    let state = state as *mut Blake2b160;
    let message = slice::from_raw_parts(message, message_size);
    ptr::read(state).update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b160_final(
    state: *const StedyBlake2b160State,
    digest: *mut u8,
) {
    let state = state as *const Blake2b160;
    let digest: &mut [u8; 20] = slice::from_raw_parts_mut(digest, 20).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b160_final_verify(
    state: *const StedyBlake2b160State,
    code: *const u8,
) -> bool {
    let state = state as *const Blake2b160;
    let code: &[u8; 20] = slice::from_raw_parts(code, 20).try_into().unwrap();
    ptr::read(state).verify(code)
}
