use {
    crate::api::{hmac_sha256, hmac_sha256_verify, HmacSha256},
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedyHmacSha256State {
    pub opaque: [u8; 224],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha256(
    key: *const u8,
    key_size: usize,
    message: *const u8,
    message_size: usize,
    code: *mut u8,
) {
    let key = slice::from_raw_parts(key, key_size);
    let message = slice::from_raw_parts(message, message_size);
    let _code = hmac_sha256(key, message);
    ptr::copy(_code.as_ptr(), code, 32);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha256_verify(
    key: *const u8,
    key_size: usize,
    message: *const u8,
    message_size: usize,
    code: *const u8,
) -> bool {
    let key = slice::from_raw_parts(key, key_size);
    let message = slice::from_raw_parts(message, message_size);
    let code: &[u8; 32] = slice::from_raw_parts(code, 32).try_into().unwrap();
    hmac_sha256_verify(key, message, code)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha256_init(
    state: *mut StedyHmacSha256State,
    key: *const u8,
    key_size: usize,
) {
    let state = state as *mut HmacSha256;
    let key = slice::from_raw_parts(key, key_size);
    ptr::write(state, HmacSha256::new(key));
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha256_update(
    state: *mut StedyHmacSha256State,
    message: *const u8,
    message_size: usize,
) {
    let state = state as *mut HmacSha256;
    let message = slice::from_raw_parts(message, message_size);
    ptr::read(state).update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha256_final(
    state: *const StedyHmacSha256State,
    code: *mut u8,
) {
    let state = state as *const HmacSha256;
    let code: &mut [u8; 32] = slice::from_raw_parts_mut(code, 32).try_into().unwrap();
    ptr::read(state).finalize_into(code);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha256_final_verify(
    state: *const StedyHmacSha256State,
    code: *const u8,
) -> bool {
    let state = state as *const HmacSha256;
    let code: &[u8; 32] = slice::from_raw_parts(code, 32).try_into().unwrap();
    ptr::read(state).verify(code)
}
