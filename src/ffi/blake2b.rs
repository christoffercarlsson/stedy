use {
    crate::api::{blake2b512, Blake2b512},
    core::{mem::size_of, ptr, slice},
};

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b512(
    message: *const u8,
    message_size: usize,
    digest: *mut u8,
) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = blake2b512(message);
    ptr::copy(_digest.as_ptr(), digest, 64);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b512_init(state: *mut u8, key: *const u8, key_size: usize) {
    let key = if key.is_null() || key_size == 0 {
        None
    } else {
        Some(slice::from_raw_parts(key, key_size))
    };
    let dest = state as *mut Blake2b512;
    let src = Blake2b512::new(key);
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b512_update(
    state: *mut u8,
    message: *const u8,
    message_size: usize,
) {
    let state = state as *mut Blake2b512;
    let message = slice::from_raw_parts(message, message_size);
    ptr::read(state).update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b512_final(state: *const u8, digest: *mut u8) {
    let state = state as *const Blake2b512;
    let digest: &mut [u8; 64] = slice::from_raw_parts_mut(digest, 64).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b512_final_verify(state: *const u8, code: *const u8) -> bool {
    let state = state as *const Blake2b512;
    let code: &[u8; 64] = slice::from_raw_parts(code, 64).try_into().unwrap();
    ptr::read(state).verify(code)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b512_state_size() -> usize {
    size_of::<Blake2b512>()
}
