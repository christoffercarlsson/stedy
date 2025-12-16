use {
    crate::api::{sha256, Sha256},
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedySha256State {
    pub opaque: [u8; 112],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha256(message: *const u8, message_size: usize, digest: *mut u8) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = sha256(message);
    ptr::copy(_digest.as_ptr(), digest, 32);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha256_init(state: *mut StedySha256State) {
    let state = state as *mut Sha256;
    ptr::write(state, Sha256::new());
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha256_update(
    state: *mut StedySha256State,
    message: *const u8,
    message_size: usize,
) {
    let state = state as *mut Sha256;
    let message = slice::from_raw_parts(message, message_size);
    ptr::read(state).update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha256_final(state: *const StedySha256State, digest: *mut u8) {
    let state = state as *const Sha256;
    let digest: &mut [u8; 32] = slice::from_raw_parts_mut(digest, 32).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}
