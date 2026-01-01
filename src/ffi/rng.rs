use {
    crate::rng::Rng,
    core::{ptr, slice},
};

#[repr(C, align(4))]
pub struct StedyRngState {
    pub opaque: [u8; 132],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_init(state: *mut StedyRngState) {
    let dest = state as *mut Rng;
    let src = Rng::seed().unwrap();
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_seed(seed: *const u8, state: *mut StedyRngState) {
    let seed: [u8; 32] = slice::from_raw_parts(seed, 32).try_into().unwrap();
    let dest = state as *mut Rng;
    let src = Rng::from(seed);
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_fill(state: *mut StedyRngState, bytes: *mut u8, size: usize) {
    let state = &mut *(state as *mut Rng);
    let bytes = slice::from_raw_parts_mut(bytes, size);
    state.fill(bytes);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_next_u32(state: *mut StedyRngState) -> u32 {
    let state = &mut *(state as *mut Rng);
    state.next_u32()
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_next_u64(state: *mut StedyRngState) -> u64 {
    let state = &mut *(state as *mut Rng);
    state.next_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_rng_init() {
        let mut state = StedyRngState { opaque: [0u8; 132] };
        let state = &mut state as *mut _;
        unsafe { stedy_rng_init(state) };
        let mut bytes = [0u8; 32];
        unsafe { stedy_rng_fill(state, bytes.as_mut_ptr(), bytes.len()) };
        assert_ne!(bytes, [0u8; 32]);
        assert_ne!(
            bytes,
            [
                164, 57, 211, 237, 179, 104, 1, 234, 36, 204, 6, 111, 41, 227, 2, 30, 141, 242,
                229, 229, 5, 91, 53, 238, 8, 215, 139, 233, 41, 127, 255, 205
            ]
        );
    }

    #[test]
    fn test_stedy_rng_fill() {
        let mut state = StedyRngState { opaque: [0u8; 132] };
        let state = &mut state as *mut _;
        let seed = [0u8; 32];
        unsafe { stedy_rng_seed(seed.as_ptr(), state) };
        let mut bytes = [0u8; 32];
        unsafe { stedy_rng_fill(state, bytes.as_mut_ptr(), bytes.len()) };
        assert_eq!(
            bytes,
            [
                164, 57, 211, 237, 179, 104, 1, 234, 36, 204, 6, 111, 41, 227, 2, 30, 141, 242,
                229, 229, 5, 91, 53, 238, 8, 215, 139, 233, 41, 127, 255, 205
            ]
        );
    }

    #[test]
    fn test_stedy_rng_next_u32() {
        let mut state = StedyRngState { opaque: [0u8; 132] };
        let state = &mut state as *mut _;
        let seed = [0u8; 32];
        unsafe { stedy_rng_seed(seed.as_ptr(), state) };
        let result = unsafe { stedy_rng_next_u32(state) };
        assert_eq!(result, 3990043044);
    }

    #[test]
    fn test_stedy_rng_next_u64() {
        let mut state = StedyRngState { opaque: [0u8; 132] };
        let state = &mut state as *mut _;
        let seed = [0u8; 32];
        unsafe { stedy_rng_seed(seed.as_ptr(), state) };
        let result = unsafe { stedy_rng_next_u64(state) };
        assert_eq!(result, 16861873601850325412);
    }
}
