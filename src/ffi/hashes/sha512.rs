use {
    crate::hashes::Sha512,
    core::{ptr, slice},
};

#[repr(C, align(8))]
pub struct StedySha512State {
    pub opaque: [u8; 208],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha512(message: *const u8, message_size: usize, digest: *mut u8) {
    let message = slice::from_raw_parts(message, message_size);
    let _digest = Sha512::digest(message);
    ptr::copy(_digest.as_ptr(), digest, 64);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha512_init(state: *mut StedySha512State) {
    let state = state as *mut Sha512;
    ptr::write(state, Sha512::new());
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha512_update(
    state: *mut StedySha512State,
    message: *const u8,
    message_size: usize,
) {
    let state = &mut *(state as *mut Sha512);
    let message = slice::from_raw_parts(message, message_size);
    state.update(message);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_sha512_final(state: *const StedySha512State, digest: *mut u8) {
    let state = state as *const Sha512;
    let digest: &mut [u8; 64] = slice::from_raw_parts_mut(digest, 64).try_into().unwrap();
    ptr::read(state).finalize_into(digest);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_sha512() {
        let message = b"abc";
        let mut digest = [0u8; 64];
        unsafe { stedy_sha512(message.as_ptr(), message.len(), digest.as_mut_ptr()) };
        assert_eq!(
            digest,
            [
                221, 175, 53, 161, 147, 97, 122, 186, 204, 65, 115, 73, 174, 32, 65, 49, 18, 230,
                250, 78, 137, 169, 126, 162, 10, 158, 238, 230, 75, 85, 211, 154, 33, 146, 153, 42,
                39, 79, 193, 168, 54, 186, 60, 35, 163, 254, 235, 189, 69, 77, 68, 35, 100, 60,
                232, 14, 42, 154, 201, 79, 165, 76, 164, 159,
            ]
        );
    }

    #[test]
    fn test_stedy_sha512_inc() {
        let mut state = StedySha512State { opaque: [0u8; 208] };
        let state = &mut state as *mut _;
        let mut digest = [0u8; 64];
        unsafe {
            stedy_sha512_init(state);
            stedy_sha512_update(state, b"a".as_ptr(), 1);
            stedy_sha512_update(state, b"b".as_ptr(), 1);
            stedy_sha512_update(state, b"c".as_ptr(), 1);
            stedy_sha512_final(state, digest.as_mut_ptr());
        };
        assert_eq!(
            digest,
            [
                221, 175, 53, 161, 147, 97, 122, 186, 204, 65, 115, 73, 174, 32, 65, 49, 18, 230,
                250, 78, 137, 169, 126, 162, 10, 158, 238, 230, 75, 85, 211, 154, 33, 146, 153, 42,
                39, 79, 193, 168, 54, 186, 60, 35, 163, 254, 235, 189, 69, 77, 68, 35, 100, 60,
                232, 14, 42, 154, 201, 79, 165, 76, 164, 159,
            ]
        );
    }
}
