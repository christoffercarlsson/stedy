use {
    crate::hashes::{Blake2b160, Blake2b256, Blake2b384, Blake2b512},
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
    let _digest = Blake2b256::digest(message);
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
    let _digest = Blake2b384::digest(message);
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
    let _digest = Blake2b512::digest(message);
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
