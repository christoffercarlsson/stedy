use {
    crate::api::{sha512, Sha512},
    core::{mem::size_of, ptr, slice},
};

#[no_mangle]
pub unsafe extern "C" fn stedy_sha512(message: *const u8, message_size: usize, digest: *mut u8) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = sha512(message);
    ptr::copy(_digest.as_ptr(), digest, 64);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha512_init(state: *mut u8) {
    let state = state as *mut Sha512;
    ptr::write(state, Sha512::new());
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha512_update(
    state: *mut u8,
    message: *const u8,
    message_size: usize,
) {
    let state = state as *mut Sha512;
    let message = slice::from_raw_parts(message, message_size);
    ptr::read(state).update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha512_final(state: *const u8, digest: *mut u8) {
    let state = state as *const Sha512;
    let digest: &mut [u8; 64] = slice::from_raw_parts_mut(digest, 64).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha512_state_size() -> usize {
    size_of::<Sha512>()
}
