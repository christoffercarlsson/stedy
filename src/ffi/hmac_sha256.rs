use {
    crate::{hmac::Hmac, sha256::Sha256},
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
    let mut mac = Hmac::<Sha256>::new(key);
    mac.update(message);
    let _code = mac.finalize();
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
    let mut mac = Hmac::<Sha256>::new(key);
    mac.update(message);
    mac.verify(code)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha256_init(
    state: *mut StedyHmacSha256State,
    key: *const u8,
    key_size: usize,
) {
    let state = state as *mut Hmac<Sha256>;
    let key = slice::from_raw_parts(key, key_size);
    ptr::write(state, Hmac::<Sha256>::new(key));
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha256_update(
    state: *mut StedyHmacSha256State,
    message: *const u8,
    message_size: usize,
) {
    let state = &mut *(state as *mut Hmac<Sha256>);
    let message = slice::from_raw_parts(message, message_size);
    state.update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha256_final(
    state: *const StedyHmacSha256State,
    code: *mut u8,
) {
    let state = state as *const Hmac<Sha256>;
    let code: &mut [u8; 32] = slice::from_raw_parts_mut(code, 32).try_into().unwrap();
    ptr::read(state).finalize_into(code);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hmac_sha256_final_verify(
    state: *const StedyHmacSha256State,
    code: *const u8,
) -> bool {
    let state = state as *const Hmac<Sha256>;
    let code: &[u8; 32] = slice::from_raw_parts(code, 32).try_into().unwrap();
    ptr::read(state).verify(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_hmac_sha256() {
        let key = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let message = [72, 105, 32, 84, 104, 101, 114, 101];
        let mut code = [0u8; 32];
        unsafe {
            stedy_hmac_sha256(
                key.as_ptr(),
                key.len(),
                message.as_ptr(),
                message.len(),
                code.as_mut_ptr(),
            )
        };
        let verified = unsafe {
            stedy_hmac_sha256_verify(
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
                176, 52, 76, 97, 216, 219, 56, 83, 92, 168, 175, 206, 175, 11, 241, 43, 136, 29,
                194, 0, 201, 131, 61, 167, 38, 233, 55, 108, 46, 50, 207, 247,
            ]
        );
    }

    #[test]
    fn test_stedy_hmac_sha256_inc() {
        let mut state = StedyHmacSha256State { opaque: [0u8; 224] };
        let state = &mut state as *mut _;
        let key = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let a = [72, 105, 32];
        let b = [84, 104, 101];
        let c = [114, 101];
        let code = [
            176, 52, 76, 97, 216, 219, 56, 83, 92, 168, 175, 206, 175, 11, 241, 43, 136, 29, 194,
            0, 201, 131, 61, 167, 38, 233, 55, 108, 46, 50, 207, 247,
        ];
        unsafe {
            stedy_hmac_sha256_init(state, key.as_ptr(), key.len());
            stedy_hmac_sha256_update(state, a.as_ptr(), a.len());
            stedy_hmac_sha256_update(state, b.as_ptr(), b.len());
            stedy_hmac_sha256_update(state, c.as_ptr(), c.len());
        };
        let verified = unsafe { stedy_hmac_sha256_final_verify(state, code.as_ptr()) };
        assert!(verified);
    }
}
