use {
    crate::api::{
        hmac_sha1, hmac_sha1_verify, hmac_sha256, hmac_sha256_verify, hmac_sha512,
        hmac_sha512_verify, HmacSha1, HmacSha256, HmacSha512,
    },
    core::{mem::size_of, ptr, slice},
};

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha1(
    key: *const u8,
    key_size: usize,
    message: *const u8,
    message_size: usize,
    code: *mut u8,
) {
    let key = slice::from_raw_parts(key, key_size);
    let message = slice::from_raw_parts(message, message_size);
    let _code = hmac_sha1(key, message);
    ptr::copy(_code.as_ptr(), code, 20);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha1_verify(
    key: *const u8,
    key_size: usize,
    message: *const u8,
    message_size: usize,
    code: *const u8,
) -> bool {
    let key = slice::from_raw_parts(key, key_size);
    let message = slice::from_raw_parts(message, message_size);
    let code: &[u8; 20] = slice::from_raw_parts(code, 20).try_into().unwrap();
    hmac_sha1_verify(key, message, code)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha1_init(state: *mut u8, key: *const u8, key_size: usize) {
    let state = state as *mut HmacSha1;
    let key = slice::from_raw_parts(key, key_size);
    ptr::write(state, HmacSha1::new(key));
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha1_update(
    state: *mut u8,
    message: *const u8,
    message_size: usize,
) {
    let state = state as *mut HmacSha1;
    let message = slice::from_raw_parts(message, message_size);
    ptr::read(state).update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha1_final(state: *const u8, code: *mut u8) {
    let state = state as *const HmacSha1;
    let code: &mut [u8; 20] = slice::from_raw_parts_mut(code, 20).try_into().unwrap();
    ptr::read(state).finalize_into(code);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha1_final_verify(state: *const u8, code: *const u8) -> bool {
    let state = state as *const HmacSha1;
    let code: &[u8; 20] = slice::from_raw_parts(code, 20).try_into().unwrap();
    ptr::read(state).verify(code)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha1_state_size() -> usize {
    size_of::<HmacSha1>()
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
pub unsafe extern "C" fn stedy_hmac_sha256_init(state: *mut u8, key: *const u8, key_size: usize) {
    let state = state as *mut HmacSha256;
    let key = slice::from_raw_parts(key, key_size);
    ptr::write(state, HmacSha256::new(key));
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha256_update(
    state: *mut u8,
    message: *const u8,
    message_size: usize,
) {
    let state = state as *mut HmacSha256;
    let message = slice::from_raw_parts(message, message_size);
    ptr::read(state).update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha256_final(state: *const u8, code: *mut u8) {
    let state = state as *const HmacSha256;
    let code: &mut [u8; 32] = slice::from_raw_parts_mut(code, 32).try_into().unwrap();
    ptr::read(state).finalize_into(code);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha256_final_verify(state: *const u8, code: *const u8) -> bool {
    let state = state as *const HmacSha256;
    let code: &[u8; 32] = slice::from_raw_parts(code, 32).try_into().unwrap();
    ptr::read(state).verify(code)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha256_state_size() -> usize {
    size_of::<HmacSha256>()
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
pub unsafe extern "C" fn stedy_hmac_sha512_init(state: *mut u8, key: *const u8, key_size: usize) {
    let state = state as *mut HmacSha512;
    let key = slice::from_raw_parts(key, key_size);
    ptr::write(state, HmacSha512::new(key));
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha512_update(
    state: *mut u8,
    message: *const u8,
    message_size: usize,
) {
    let state = state as *mut HmacSha512;
    let message = slice::from_raw_parts(message, message_size);
    ptr::read(state).update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha512_final(state: *const u8, code: *mut u8) {
    let state = state as *const HmacSha512;
    let code: &mut [u8; 64] = slice::from_raw_parts_mut(code, 64).try_into().unwrap();
    ptr::read(state).finalize_into(code);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha512_final_verify(state: *const u8, code: *const u8) -> bool {
    let state = state as *const HmacSha512;
    let code: &[u8; 64] = slice::from_raw_parts(code, 64).try_into().unwrap();
    ptr::read(state).verify(&code)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha512_state_size() -> usize {
    size_of::<HmacSha512>()
}
