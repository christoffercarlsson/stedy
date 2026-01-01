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
    let state = &mut *(state as *mut HmacSha512);
    let message = slice::from_raw_parts(message, message_size);
    state.update(message);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_hmac_sha512() {
        let key = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let message = [72, 105, 32, 84, 104, 101, 114, 101];
        let mut code = [0u8; 64];
        unsafe {
            stedy_hmac_sha512(
                key.as_ptr(),
                key.len(),
                message.as_ptr(),
                message.len(),
                code.as_mut_ptr(),
            )
        };
        let verified = unsafe {
            stedy_hmac_sha512_verify(
                key.as_ptr(),
                key.len(),
                message.as_ptr(),
                message.len(),
                code.as_ptr(),
            )
        };
        assert!(verified);
        assert_eq!(
            code,
            [
                135, 170, 124, 222, 165, 239, 97, 157, 79, 240, 180, 36, 26, 29, 108, 176, 35, 121,
                244, 226, 206, 78, 194, 120, 122, 208, 179, 5, 69, 225, 124, 222, 218, 168, 51,
                183, 214, 184, 167, 2, 3, 139, 39, 78, 174, 163, 244, 228, 190, 157, 145, 78, 235,
                97, 241, 112, 46, 105, 108, 32, 58, 18, 104, 84,
            ]
        );
    }

    #[test]
    fn test_stedy_hmac_sha256_inc() {
        let mut state = StedyHmacSha512State { opaque: [0u8; 416] };
        let state = &mut state as *mut _;
        let key = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let a = [72, 105, 32];
        let b = [84, 104, 101];
        let c = [114, 101];
        let code = [
            135, 170, 124, 222, 165, 239, 97, 157, 79, 240, 180, 36, 26, 29, 108, 176, 35, 121,
            244, 226, 206, 78, 194, 120, 122, 208, 179, 5, 69, 225, 124, 222, 218, 168, 51, 183,
            214, 184, 167, 2, 3, 139, 39, 78, 174, 163, 244, 228, 190, 157, 145, 78, 235, 97, 241,
            112, 46, 105, 108, 32, 58, 18, 104, 84,
        ];
        unsafe {
            stedy_hmac_sha512_init(state, key.as_ptr(), key.len());
            stedy_hmac_sha512_update(state, a.as_ptr(), a.len());
            stedy_hmac_sha512_update(state, b.as_ptr(), b.len());
            stedy_hmac_sha512_update(state, c.as_ptr(), c.len());
        };
        let verified = unsafe { stedy_hmac_sha512_final_verify(state, code.as_ptr()) };
        assert!(verified);
    }
}
