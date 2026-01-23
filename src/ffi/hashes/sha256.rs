use {
    crate::hashes::Sha256,
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedySha256State {
    pub opaque: [u8; 112],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha256(message: *const u8, message_size: usize, digest: *mut u8) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = Sha256::digest(message);
    ptr::copy(_digest.as_ptr(), digest, 32);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha256_init(state: *mut StedySha256State) {
    let state = state as *mut Sha256;
    ptr::write(state, Sha256::new());
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha256_update(
    state: *mut StedySha256State,
    message: *const u8,
    message_size: usize,
) {
    let state = &mut *(state as *mut Sha256);
    let message = slice::from_raw_parts(message, message_size);
    state.update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha256_final(state: *const StedySha256State, digest: *mut u8) {
    let state = state as *const Sha256;
    let digest: &mut [u8; 32] = slice::from_raw_parts_mut(digest, 32).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_sha256() {
        let message = b"abc";
        let mut digest = [0u8; 32];
        unsafe { stedy_sha256(message.as_ptr(), message.len(), digest.as_mut_ptr()) };
        assert_eq!(
            digest,
            [
                186, 120, 22, 191, 143, 1, 207, 234, 65, 65, 64, 222, 93, 174, 34, 35, 176, 3, 97,
                163, 150, 23, 122, 156, 180, 16, 255, 97, 242, 0, 21, 173,
            ]
        );
    }

    #[test]
    fn test_stedy_sha256_inc() {
        let mut state = StedySha256State { opaque: [0u8; 112] };
        let state = &mut state as *mut _;
        let mut digest = [0u8; 32];
        unsafe {
            stedy_sha256_init(state);
            stedy_sha256_update(state, b"a".as_ptr(), 1);
            stedy_sha256_update(state, b"b".as_ptr(), 1);
            stedy_sha256_update(state, b"c".as_ptr(), 1);
            stedy_sha256_final(state, digest.as_mut_ptr());
        };
        assert_eq!(
            digest,
            [
                186, 120, 22, 191, 143, 1, 207, 234, 65, 65, 64, 222, 93, 174, 34, 35, 176, 3, 97,
                163, 150, 23, 122, 156, 180, 16, 255, 97, 242, 0, 21, 173,
            ]
        );
    }
}
