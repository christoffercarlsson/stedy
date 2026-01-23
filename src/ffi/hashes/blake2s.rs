use {
    crate::hashes::{Blake2s128, Blake2s160, Blake2s224, Blake2s256},
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedyBlake2s128State {
    pub opaque: [u8; 112],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s128(
    message: *const u8,
    message_size: usize,
    digest: *mut u8,
) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = Blake2s128::digest(message);
    ptr::copy(_digest.as_ptr(), digest, 16);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s128_init(
    state: *mut StedyBlake2s128State,
    key: *const u8,
    key_size: usize,
) {
    let key = if key.is_null() || key_size == 0 {
        None
    } else {
        Some(slice::from_raw_parts(key, key_size))
    };
    let dest = state as *mut Blake2s128;
    let src = Blake2s128::new(key);
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s128_update(
    state: *mut StedyBlake2s128State,
    message: *const u8,
    message_size: usize,
) {
    let state = &mut *(state as *mut Blake2s128);
    let message = slice::from_raw_parts(message, message_size);
    state.update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s128_final(
    state: *const StedyBlake2s128State,
    digest: *mut u8,
) {
    let state = state as *const Blake2s128;
    let digest: &mut [u8; 16] = slice::from_raw_parts_mut(digest, 16).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_blake2s128_final_verify(
    state: *const StedyBlake2s128State,
    code: *const u8,
) -> bool {
    let state = state as *const Blake2s128;
    let code: &[u8; 16] = slice::from_raw_parts(code, 16).try_into().unwrap();
    ptr::read(state).verify(code)
}

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
    let _digest = Blake2s224::digest(message);
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
    fn test_stedy_blake2s128() {
        let message = b"abc";
        let mut digest = [0u8; 16];
        unsafe { stedy_blake2s128(message.as_ptr(), message.len(), digest.as_mut_ptr()) };
        assert_eq!(
            digest,
            [170, 73, 56, 17, 155, 29, 199, 184, 124, 186, 208, 255, 210, 0, 208, 174],
        );
    }

    #[test]
    fn test_stedy_blake2s128_inc() {
        let mut state = StedyBlake2s128State { opaque: [0u8; 112] };
        let state = &mut state as *mut _;
        let mut digest = [0u8; 16];
        unsafe {
            stedy_blake2s128_init(state, core::ptr::null(), 0);
            stedy_blake2s128_update(state, b"a".as_ptr(), 1);
            stedy_blake2s128_update(state, b"b".as_ptr(), 1);
            stedy_blake2s128_update(state, b"c".as_ptr(), 1);
            stedy_blake2s128_final(state, digest.as_mut_ptr());
        };
        assert_eq!(
            digest,
            [170, 73, 56, 17, 155, 29, 199, 184, 124, 186, 208, 255, 210, 0, 208, 174],
        );
    }

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
