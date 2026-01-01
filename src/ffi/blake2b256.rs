use {
    crate::blake2b::{blake2b256, Blake2b256},
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedyBlake2b256State {
    pub opaque: [u8; 216],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b256(
    message: *const u8,
    message_size: usize,
    digest: *mut u8,
) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = blake2b256(message);
    ptr::copy(_digest.as_ptr(), digest, 32);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b256_init(
    state: *mut StedyBlake2b256State,
    key: *const u8,
    key_size: usize,
) {
    let key = if key.is_null() || key_size == 0 {
        None
    } else {
        Some(slice::from_raw_parts(key, key_size))
    };
    let dest = state as *mut Blake2b256;
    let src = Blake2b256::new(key);
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b256_update(
    state: *mut StedyBlake2b256State,
    message: *const u8,
    message_size: usize,
) {
    let state = &mut *(state as *mut Blake2b256);
    let message = slice::from_raw_parts(message, message_size);
    state.update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b256_final(
    state: *const StedyBlake2b256State,
    digest: *mut u8,
) {
    let state = state as *const Blake2b256;
    let digest: &mut [u8; 32] = slice::from_raw_parts_mut(digest, 32).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b256_final_verify(
    state: *const StedyBlake2b256State,
    code: *const u8,
) -> bool {
    let state = state as *const Blake2b256;
    let code: &[u8; 32] = slice::from_raw_parts(code, 32).try_into().unwrap();
    ptr::read(state).verify(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_blake2b256() {
        let message = b"abc";
        let mut digest = [0u8; 32];
        unsafe { stedy_blake2b256(message.as_ptr(), message.len(), digest.as_mut_ptr()) };
        assert_eq!(
            digest,
            [
                189, 221, 129, 60, 99, 66, 57, 114, 49, 113, 239, 63, 238, 152, 87, 155, 148, 150,
                78, 59, 177, 203, 62, 66, 114, 98, 200, 192, 104, 213, 35, 25
            ]
        );
    }

    #[test]
    fn test_stedy_blake2b256_inc() {
        let mut state = StedyBlake2b256State { opaque: [0u8; 216] };
        let state = &mut state as *mut _;
        let mut digest = [0u8; 32];
        unsafe {
            stedy_blake2b256_init(state, core::ptr::null(), 0);
            stedy_blake2b256_update(state, b"a".as_ptr(), 1);
            stedy_blake2b256_update(state, b"b".as_ptr(), 1);
            stedy_blake2b256_update(state, b"c".as_ptr(), 1);
            stedy_blake2b256_final(state, digest.as_mut_ptr());
        };
        assert_eq!(
            digest,
            [
                189, 221, 129, 60, 99, 66, 57, 114, 49, 113, 239, 63, 238, 152, 87, 155, 148, 150,
                78, 59, 177, 203, 62, 66, 114, 98, 200, 192, 104, 213, 35, 25
            ]
        );
    }
}
