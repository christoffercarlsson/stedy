use {
    crate::blake2b::{blake2b512, Blake2b512},
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedyBlake2b512State {
    pub opaque: [u8; 216],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b512(
    message: *const u8,
    message_size: usize,
    digest: *mut u8,
) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = blake2b512(message);
    ptr::copy(_digest.as_ptr(), digest, 64);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b512_init(
    state: *mut StedyBlake2b512State,
    key: *const u8,
    key_size: usize,
) {
    let key = if key.is_null() || key_size == 0 {
        None
    } else {
        Some(slice::from_raw_parts(key, key_size))
    };
    let dest = state as *mut Blake2b512;
    let src = Blake2b512::new(key);
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b512_update(
    state: *mut StedyBlake2b512State,
    message: *const u8,
    message_size: usize,
) {
    let state = &mut *(state as *mut Blake2b512);
    let message = slice::from_raw_parts(message, message_size);
    state.update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b512_final(
    state: *const StedyBlake2b512State,
    digest: *mut u8,
) {
    let state = state as *const Blake2b512;
    let digest: &mut [u8; 64] = slice::from_raw_parts_mut(digest, 64).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b512_final_verify(
    state: *const StedyBlake2b512State,
    code: *const u8,
) -> bool {
    let state = state as *const Blake2b512;
    let code: &[u8; 64] = slice::from_raw_parts(code, 64).try_into().unwrap();
    ptr::read(state).verify(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_blake2b512() {
        let message = b"abc";
        let mut digest = [0u8; 64];
        unsafe { stedy_blake2b512(message.as_ptr(), message.len(), digest.as_mut_ptr()) };
        assert_eq!(
            digest,
            [
                186, 128, 165, 63, 152, 28, 77, 13, 106, 39, 151, 182, 159, 18, 246, 233, 76, 33,
                47, 20, 104, 90, 196, 183, 75, 18, 187, 111, 219, 255, 162, 209, 125, 135, 197, 57,
                42, 171, 121, 45, 194, 82, 213, 222, 69, 51, 204, 149, 24, 211, 138, 168, 219, 241,
                146, 90, 185, 35, 134, 237, 212, 0, 153, 35
            ]
        );
    }

    #[test]
    fn test_stedy_blake2b512_inc() {
        let mut state = StedyBlake2b512State { opaque: [0u8; 216] };
        let state = &mut state as *mut _;
        let mut digest = [0u8; 64];
        unsafe {
            stedy_blake2b512_init(state, core::ptr::null(), 0);
            stedy_blake2b512_update(state, b"a".as_ptr(), 1);
            stedy_blake2b512_update(state, b"b".as_ptr(), 1);
            stedy_blake2b512_update(state, b"c".as_ptr(), 1);
            stedy_blake2b512_final(state, digest.as_mut_ptr());
        };
        assert_eq!(
            digest,
            [
                186, 128, 165, 63, 152, 28, 77, 13, 106, 39, 151, 182, 159, 18, 246, 233, 76, 33,
                47, 20, 104, 90, 196, 183, 75, 18, 187, 111, 219, 255, 162, 209, 125, 135, 197, 57,
                42, 171, 121, 45, 194, 82, 213, 222, 69, 51, 204, 149, 24, 211, 138, 168, 219, 241,
                146, 90, 185, 35, 134, 237, 212, 0, 153, 35
            ]
        );
    }
}
