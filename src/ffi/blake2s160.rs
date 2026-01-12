use {
    crate::blake2s::Blake2s160,
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedyBlake2s160State {
    pub opaque: [u8; 112],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s160(
    message: *const u8,
    message_size: usize,
    digest: *mut u8,
) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = Blake2s160::digest(message);
    ptr::copy(_digest.as_ptr(), digest, 20);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s160_init(
    state: *mut StedyBlake2s160State,
    key: *const u8,
    key_size: usize,
) {
    let key = if key.is_null() || key_size == 0 {
        None
    } else {
        Some(slice::from_raw_parts(key, key_size))
    };
    let dest = state as *mut Blake2s160;
    let src = Blake2s160::new(key);
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s160_update(
    state: *mut StedyBlake2s160State,
    message: *const u8,
    message_size: usize,
) {
    let state = &mut *(state as *mut Blake2s160);
    let message = slice::from_raw_parts(message, message_size);
    state.update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s160_final(
    state: *const StedyBlake2s160State,
    digest: *mut u8,
) {
    let state = state as *const Blake2s160;
    let digest: &mut [u8; 20] = slice::from_raw_parts_mut(digest, 20).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s160_final_verify(
    state: *const StedyBlake2s160State,
    code: *const u8,
) -> bool {
    let state = state as *const Blake2s160;
    let code: &[u8; 20] = slice::from_raw_parts(code, 20).try_into().unwrap();
    ptr::read(state).verify(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_blake2s160() {
        let message = b"abc";
        let mut digest = [0u8; 20];
        unsafe { stedy_blake2s160(message.as_ptr(), message.len(), digest.as_mut_ptr()) };
        assert_eq!(
            digest,
            [
                90, 227, 185, 155, 226, 155, 1, 131, 76, 59, 80, 133, 33, 237, 230, 4, 56, 248,
                222, 23
            ]
        );
    }

    #[test]
    fn test_stedy_blake2s160_inc() {
        let mut state = StedyBlake2s160State { opaque: [0u8; 112] };
        let state = &mut state as *mut _;
        let mut digest = [0u8; 20];
        unsafe {
            stedy_blake2s160_init(state, core::ptr::null(), 0);
            stedy_blake2s160_update(state, b"a".as_ptr(), 1);
            stedy_blake2s160_update(state, b"b".as_ptr(), 1);
            stedy_blake2s160_update(state, b"c".as_ptr(), 1);
            stedy_blake2s160_final(state, digest.as_mut_ptr());
        };
        assert_eq!(
            digest,
            [
                90, 227, 185, 155, 226, 155, 1, 131, 76, 59, 80, 133, 33, 237, 230, 4, 56, 248,
                222, 23
            ]
        );
    }
}
