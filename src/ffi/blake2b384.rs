use {
    crate::blake2b::{blake2b384, Blake2b384},
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedyBlake2b384State {
    pub opaque: [u8; 216],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b384(
    message: *const u8,
    message_size: usize,
    digest: *mut u8,
) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = blake2b384(message);
    ptr::copy(_digest.as_ptr(), digest, 48);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b384_init(
    state: *mut StedyBlake2b384State,
    key: *const u8,
    key_size: usize,
) {
    let key = if key.is_null() || key_size == 0 {
        None
    } else {
        Some(slice::from_raw_parts(key, key_size))
    };
    let dest = state as *mut Blake2b384;
    let src = Blake2b384::new(key);
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b384_update(
    state: *mut StedyBlake2b384State,
    message: *const u8,
    message_size: usize,
) {
    let state = &mut *(state as *mut Blake2b384);
    let message = slice::from_raw_parts(message, message_size);
    state.update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b384_final(
    state: *const StedyBlake2b384State,
    digest: *mut u8,
) {
    let state = state as *const Blake2b384;
    let digest: &mut [u8; 48] = slice::from_raw_parts_mut(digest, 48).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b384_final_verify(
    state: *const StedyBlake2b384State,
    code: *const u8,
) -> bool {
    let state = state as *const Blake2b384;
    let code: &[u8; 48] = slice::from_raw_parts(code, 48).try_into().unwrap();
    ptr::read(state).verify(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_blake2b384() {
        let message = b"abc";
        let mut digest = [0u8; 48];
        unsafe { stedy_blake2b384(message.as_ptr(), message.len(), digest.as_mut_ptr()) };
        assert_eq!(
            digest,
            [
                111, 86, 168, 44, 142, 126, 245, 38, 223, 225, 130, 235, 82, 18, 247, 219, 157,
                241, 49, 126, 87, 129, 93, 189, 164, 96, 131, 252, 48, 245, 78, 230, 198, 107, 168,
                59, 230, 75, 48, 45, 124, 186, 108, 225, 91, 181, 86, 244
            ]
        );
    }

    #[test]
    fn test_stedy_blake2b384_inc() {
        let mut state = StedyBlake2b384State { opaque: [0u8; 216] };
        let state = &mut state as *mut _;
        let mut digest = [0u8; 48];
        unsafe {
            stedy_blake2b384_init(state, core::ptr::null(), 0);
            stedy_blake2b384_update(state, b"a".as_ptr(), 1);
            stedy_blake2b384_update(state, b"b".as_ptr(), 1);
            stedy_blake2b384_update(state, b"c".as_ptr(), 1);
            stedy_blake2b384_final(state, digest.as_mut_ptr());
        };
        assert_eq!(
            digest,
            [
                111, 86, 168, 44, 142, 126, 245, 38, 223, 225, 130, 235, 82, 18, 247, 219, 157,
                241, 49, 126, 87, 129, 93, 189, 164, 96, 131, 252, 48, 245, 78, 230, 198, 107, 168,
                59, 230, 75, 48, 45, 124, 186, 108, 225, 91, 181, 86, 244
            ]
        );
    }
}
