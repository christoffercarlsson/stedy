use {
    crate::csprng::Rng,
    core::{ptr, slice},
};

#[repr(C, align(4))]
pub struct StedyRngState {
    pub opaque: [u8; 132],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_seed(
    seed: *const u8,
    seed_size: usize,
    state: *mut StedyRngState,
) -> bool {
    let seed = slice::from_raw_parts(seed, seed_size);
    let dest = state as *mut Rng;
    if let Some(src) = Rng::new(seed) {
        ptr::write(dest, src);
        true
    } else {
        false
    }
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
    fn test_stedy_rng_fill() {
        let mut state = StedyRngState { opaque: [0u8; 132] };
        let state = &mut state as *mut _;
        let seed = [0u8; 96];
        unsafe { stedy_rng_seed(seed.as_ptr(), 96, state) };
        let mut bytes = [0u8; 32];
        unsafe { stedy_rng_fill(state, bytes.as_mut_ptr(), bytes.len()) };
        assert_eq!(
            bytes,
            [
                189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102,
                238, 246, 149, 42, 27, 28, 74, 169, 187, 175, 23, 175, 195, 58, 204
            ]
        );
    }

    #[test]
    fn test_stedy_rng_next_u32() {
        let mut state = StedyRngState { opaque: [0u8; 132] };
        let state = &mut state as *mut _;
        let seed = [0u8; 96];
        unsafe { stedy_rng_seed(seed.as_ptr(), 96, state) };
        let result = unsafe { stedy_rng_next_u32(state) };
        assert_eq!(result, 1987994301);
    }

    #[test]
    fn test_stedy_rng_next_u64() {
        let mut state = StedyRngState { opaque: [0u8; 132] };
        let state = &mut state as *mut _;
        let seed = [0u8; 96];
        unsafe { stedy_rng_seed(seed.as_ptr(), 96, state) };
        let result = unsafe { stedy_rng_next_u64(state) };
        assert_eq!(result, 7751686179014992573);
    }
}
