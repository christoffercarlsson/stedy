use {
    crate::api::{sha256, Sha256},
    core::{mem::size_of, ptr, slice},
};

#[no_mangle]
pub unsafe extern "C" fn stedy_sha256(message: *const u8, message_size: usize, digest: *mut u8) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = sha256(message);
    ptr::copy(_digest.as_ptr(), digest, 32);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha256_init(state: *mut u8) {
    let state = state as *mut Sha256;
    ptr::write(state, Sha256::new());
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha256_update(
    state: *mut u8,
    message: *const u8,
    message_size: usize,
) {
    let state = state as *mut Sha256;
    let message = slice::from_raw_parts(message, message_size);
    ptr::read(state).update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha256_final(state: *const u8, digest: *mut u8) {
    let state = state as *const Sha256;
    let digest: &mut [u8; 32] = slice::from_raw_parts_mut(digest, 32).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha256_state_size() -> usize {
    size_of::<Sha256>()
}
