use {
    crate::blake2s::Blake2s256,
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedyBlake2s256State {
    pub opaque: [u8; 112],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s256(
    message: *const u8,
    message_size: usize,
    digest: *mut u8,
) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = Blake2s256::digest(message);
    ptr::copy(_digest.as_ptr(), digest, 32);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s256_init(
    state: *mut StedyBlake2s256State,
    key: *const u8,
    key_size: usize,
) {
    let key = if key.is_null() || key_size == 0 {
        None
    } else {
        Some(slice::from_raw_parts(key, key_size))
    };
    let dest = state as *mut Blake2s256;
    let src = Blake2s256::new(key);
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s256_update(
    state: *mut StedyBlake2s256State,
    message: *const u8,
    message_size: usize,
) {
    let state = &mut *(state as *mut Blake2s256);
    let message = slice::from_raw_parts(message, message_size);
    state.update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s256_final(
    state: *const StedyBlake2s256State,
    digest: *mut u8,
) {
    let state = state as *const Blake2s256;
    let digest: &mut [u8; 32] = slice::from_raw_parts_mut(digest, 32).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s256_final_verify(
    state: *const StedyBlake2s256State,
    code: *const u8,
) -> bool {
    let state = state as *const Blake2s256;
    let code: &[u8; 32] = slice::from_raw_parts(code, 32).try_into().unwrap();
    ptr::read(state).verify(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_blake2s256() {
        let message = b"abc";
        let mut digest = [0u8; 32];
        unsafe { stedy_blake2s256(message.as_ptr(), message.len(), digest.as_mut_ptr()) };
        assert_eq!(
            digest,
            [
                80, 140, 94, 140, 50, 124, 20, 226, 225, 167, 43, 163, 78, 235, 69, 47, 55, 69,
                139, 32, 158, 214, 58, 41, 77, 153, 155, 76, 134, 103, 89, 130
            ]
        );
    }

    #[test]
    fn test_stedy_blake2s256_inc() {
        let mut state = StedyBlake2s256State { opaque: [0u8; 112] };
        let state = &mut state as *mut _;
        let mut digest = [0u8; 32];
        unsafe {
            stedy_blake2s256_init(state, core::ptr::null(), 0);
            stedy_blake2s256_update(state, b"a".as_ptr(), 1);
            stedy_blake2s256_update(state, b"b".as_ptr(), 1);
            stedy_blake2s256_update(state, b"c".as_ptr(), 1);
            stedy_blake2s256_final(state, digest.as_mut_ptr());
        };
        assert_eq!(
            digest,
            [
                80, 140, 94, 140, 50, 124, 20, 226, 225, 167, 43, 163, 78, 235, 69, 47, 55, 69,
                139, 32, 158, 214, 58, 41, 77, 153, 155, 76, 134, 103, 89, 130
            ]
        );
    }
}
