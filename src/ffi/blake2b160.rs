use {
    crate::blake2b::Blake2b160,
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedyBlake2b160State {
    pub opaque: [u8; 216],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b160(
    message: *const u8,
    message_size: usize,
    digest: *mut u8,
) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = Blake2b160::digest(message);
    ptr::copy(_digest.as_ptr(), digest, 20);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b160_init(
    state: *mut StedyBlake2b160State,
    key: *const u8,
    key_size: usize,
) {
    let key = if key.is_null() || key_size == 0 {
        None
    } else {
        Some(slice::from_raw_parts(key, key_size))
    };
    let dest = state as *mut Blake2b160;
    let src = Blake2b160::new(key);
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b160_update(
    state: *mut StedyBlake2b160State,
    message: *const u8,
    message_size: usize,
) {
    let state = &mut *(state as *mut Blake2b160);
    let message = slice::from_raw_parts(message, message_size);
    state.update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b160_final(
    state: *const StedyBlake2b160State,
    digest: *mut u8,
) {
    let state = state as *const Blake2b160;
    let digest: &mut [u8; 20] = slice::from_raw_parts_mut(digest, 20).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2b160_final_verify(
    state: *const StedyBlake2b160State,
    code: *const u8,
) -> bool {
    let state = state as *const Blake2b160;
    let code: &[u8; 20] = slice::from_raw_parts(code, 20).try_into().unwrap();
    ptr::read(state).verify(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_blake2b160() {
        let message = b"abc";
        let mut digest = [0u8; 20];
        unsafe { stedy_blake2b160(message.as_ptr(), message.len(), digest.as_mut_ptr()) };
        assert_eq!(
            digest,
            [
                56, 66, 100, 246, 118, 243, 149, 54, 132, 5, 35, 242, 132, 146, 28, 220, 104, 182,
                132, 107
            ]
        );
    }

    #[test]
    fn test_stedy_blake2b160_inc() {
        let mut state = StedyBlake2b160State { opaque: [0u8; 216] };
        let state = &mut state as *mut _;
        let mut digest = [0u8; 20];
        unsafe {
            stedy_blake2b160_init(state, core::ptr::null(), 0);
            stedy_blake2b160_update(state, b"a".as_ptr(), 1);
            stedy_blake2b160_update(state, b"b".as_ptr(), 1);
            stedy_blake2b160_update(state, b"c".as_ptr(), 1);
            stedy_blake2b160_final(state, digest.as_mut_ptr());
        };
        assert_eq!(
            digest,
            [
                56, 66, 100, 246, 118, 243, 149, 54, 132, 5, 35, 242, 132, 146, 28, 220, 104, 182,
                132, 107
            ]
        );
    }
}
