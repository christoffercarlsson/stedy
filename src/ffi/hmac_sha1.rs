use {
    crate::hmac::{hmac_sha1, hmac_sha1_verify, HmacSha1},
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedyHmacSha1State {
    pub opaque: [u8; 192],
}

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
pub unsafe extern "C" fn stedy_hmac_sha1_init(
    state: *mut StedyHmacSha1State,
    key: *const u8,
    key_size: usize,
) {
    let state = state as *mut HmacSha1;
    let key = slice::from_raw_parts(key, key_size);
    ptr::write(state, HmacSha1::new(key));
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha1_update(
    state: *mut StedyHmacSha1State,
    message: *const u8,
    message_size: usize,
) {
    let state = &mut *(state as *mut HmacSha1);
    let message = slice::from_raw_parts(message, message_size);
    state.update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha1_final(state: *const StedyHmacSha1State, code: *mut u8) {
    let state = state as *const HmacSha1;
    let code: &mut [u8; 20] = slice::from_raw_parts_mut(code, 20).try_into().unwrap();
    ptr::read(state).finalize_into(code);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha1_final_verify(
    state: *const StedyHmacSha1State,
    code: *const u8,
) -> bool {
    let state = state as *const HmacSha1;
    let code: &[u8; 20] = slice::from_raw_parts(code, 20).try_into().unwrap();
    ptr::read(state).verify(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_hmac_sha1() {
        let key = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let message = [72, 105, 32, 84, 104, 101, 114, 101];
        let mut code = [0u8; 20];
        unsafe {
            stedy_hmac_sha1(
                key.as_ptr(),
                key.len(),
                message.as_ptr(),
                message.len(),
                code.as_mut_ptr(),
            )
        };
        let verified = unsafe {
            stedy_hmac_sha1_verify(
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
                182, 23, 49, 134, 85, 5, 114, 100, 226, 139, 192, 182, 251, 55, 140, 142, 241, 70,
                190, 0
            ]
        );
    }

    #[test]
    fn test_stedy_hmac_sha1_inc() {
        let mut state = StedyHmacSha1State { opaque: [0u8; 192] };
        let state = &mut state as *mut _;
        let key = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let a = [72, 105, 32];
        let b = [84, 104, 101];
        let c = [114, 101];
        let code = [
            182, 23, 49, 134, 85, 5, 114, 100, 226, 139, 192, 182, 251, 55, 140, 142, 241, 70, 190,
            0,
        ];
        unsafe {
            stedy_hmac_sha1_init(state, key.as_ptr(), key.len());
            stedy_hmac_sha1_update(state, a.as_ptr(), a.len());
            stedy_hmac_sha1_update(state, b.as_ptr(), b.len());
            stedy_hmac_sha1_update(state, c.as_ptr(), c.len());
        };
        let verified = unsafe { stedy_hmac_sha1_final_verify(state, code.as_ptr()) };
        assert!(verified);
    }
}
