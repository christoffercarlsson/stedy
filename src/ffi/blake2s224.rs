use {
    crate::blake2s::{blake2s224, Blake2s224},
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedyBlake2s224State {
    pub opaque: [u8; 112],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s224(
    message: *const u8,
    message_size: usize,
    digest: *mut u8,
) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = blake2s224(message);
    ptr::copy(_digest.as_ptr(), digest, 28);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s224_init(
    state: *mut StedyBlake2s224State,
    key: *const u8,
    key_size: usize,
) {
    let key = if key.is_null() || key_size == 0 {
        None
    } else {
        Some(slice::from_raw_parts(key, key_size))
    };
    let dest = state as *mut Blake2s224;
    let src = Blake2s224::new(key);
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s224_update(
    state: *mut StedyBlake2s224State,
    message: *const u8,
    message_size: usize,
) {
    let state = &mut *(state as *mut Blake2s224);
    let message = slice::from_raw_parts(message, message_size);
    state.update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s224_final(
    state: *const StedyBlake2s224State,
    digest: *mut u8,
) {
    let state = state as *const Blake2s224;
    let digest: &mut [u8; 28] = slice::from_raw_parts_mut(digest, 28).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s224_final_verify(
    state: *const StedyBlake2s224State,
    code: *const u8,
) -> bool {
    let state = state as *const Blake2s224;
    let code: &[u8; 28] = slice::from_raw_parts(code, 28).try_into().unwrap();
    ptr::read(state).verify(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_blake2s224() {
        let message = b"abc";
        let mut digest = [0u8; 28];
        unsafe { stedy_blake2s224(message.as_ptr(), message.len(), digest.as_mut_ptr()) };
        assert_eq!(
            digest,
            [
                11, 3, 63, 194, 38, 223, 122, 189, 226, 159, 103, 160, 93, 61, 198, 44, 242, 113,
                239, 61, 254, 164, 211, 135, 64, 127, 189, 85
            ]
        );
    }

    #[test]
    fn test_stedy_blake2s224_inc() {
        let mut state = StedyBlake2s224State { opaque: [0u8; 112] };
        let state = &mut state as *mut _;
        let mut digest = [0u8; 28];
        unsafe {
            stedy_blake2s224_init(state, core::ptr::null(), 0);
            stedy_blake2s224_update(state, b"a".as_ptr(), 1);
            stedy_blake2s224_update(state, b"b".as_ptr(), 1);
            stedy_blake2s224_update(state, b"c".as_ptr(), 1);
            stedy_blake2s224_final(state, digest.as_mut_ptr());
        };
        assert_eq!(
            digest,
            [
                11, 3, 63, 194, 38, 223, 122, 189, 226, 159, 103, 160, 93, 61, 198, 44, 242, 113,
                239, 61, 254, 164, 211, 135, 64, 127, 189, 85
            ]
        );
    }
}
