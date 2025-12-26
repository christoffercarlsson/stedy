use {
    crate::hmac::{hmac_sha512, hmac_sha512_verify, HmacSha512},
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedyHmacSha512State {
    pub opaque: [u8; 416],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha512(
    key: *const u8,
    key_size: usize,
    message: *const u8,
    message_size: usize,
    code: *mut u8,
) {
    let key = slice::from_raw_parts(key, key_size);
    let message = slice::from_raw_parts(message, message_size);
    let _code = hmac_sha512(key, message);
    ptr::copy(_code.as_ptr(), code, 64);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha512_verify(
    key: *const u8,
    key_size: usize,
    message: *const u8,
    message_size: usize,
    code: *const u8,
) -> bool {
    let key = slice::from_raw_parts(key, key_size);
    let message = slice::from_raw_parts(message, message_size);
    let code: &[u8; 64] = slice::from_raw_parts(code, 64).try_into().unwrap();
    hmac_sha512_verify(key, message, code)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha512_init(
    state: *mut StedyHmacSha512State,
    key: *const u8,
    key_size: usize,
) {
    let state = state as *mut HmacSha512;
    let key = slice::from_raw_parts(key, key_size);
    ptr::write(state, HmacSha512::new(key));
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha512_update(
    state: *mut StedyHmacSha512State,
    message: *const u8,
    message_size: usize,
) {
    let state = state as *mut HmacSha512;
    let message = slice::from_raw_parts(message, message_size);
    ptr::read(state).update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha512_final(
    state: *const StedyHmacSha512State,
    code: *mut u8,
) {
    let state = state as *const HmacSha512;
    let code: &mut [u8; 64] = slice::from_raw_parts_mut(code, 64).try_into().unwrap();
    ptr::read(state).finalize_into(code);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha512_final_verify(
    state: *const StedyHmacSha512State,
    code: *const u8,
) -> bool {
    let state = state as *const HmacSha512;
    let code: &[u8; 64] = slice::from_raw_parts(code, 64).try_into().unwrap();
    ptr::read(state).verify(&code)
}
