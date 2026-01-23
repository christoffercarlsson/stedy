use {
    crate::csprngs::Rng,
    core::{ptr, slice},
};

#[repr(C, align(4))]
pub struct StedyRngState {
    pub opaque: [u8; 132],
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_seed(state: *mut StedyRngState) {
    let dest = state as *mut Rng;
    let src = Rng::seed();
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_reseed(state: *mut StedyRngState) {
    let state = &mut *(state as *mut Rng);
    state.reseed();
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_from(seed: *const u8, state: *mut StedyRngState) {
    let seed: &[u8; 128] = slice::from_raw_parts(seed, 128).try_into().unwrap();
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
    fn test_stedy_rng_seed() {
        let mut state = StedyRngState { opaque: [0u8; 132] };
        let state = &mut state as *mut _;
        unsafe { stedy_rng_seed(state) };
        let mut a = [0u8; 32];
        unsafe { stedy_rng_fill(state, a.as_mut_ptr(), a.len()) };
        assert_ne!(
            a,
            [
                89, 151, 243, 239, 17, 196, 251, 133, 30, 56, 89, 220, 74, 144, 209, 105, 150, 125,
                139, 44, 132, 127, 191, 13, 64, 39, 240, 246, 10, 240, 124, 104
            ]
        );
        unsafe { stedy_rng_reseed(state) };
        let mut b = [0u8; 32];
        unsafe { stedy_rng_fill(state, b.as_mut_ptr(), b.len()) };
        assert_ne!(a, b);
    }

    #[test]
    fn test_stedy_rng_fill() {
        let mut state = StedyRngState { opaque: [0u8; 132] };
        let state = &mut state as *mut _;
        let seed = [0u8; 128];
        unsafe { stedy_rng_from(seed.as_ptr(), state) };
        let mut bytes = [0u8; 32];
        unsafe { stedy_rng_fill(state, bytes.as_mut_ptr(), bytes.len()) };
        assert_eq!(
            bytes,
            [
                89, 151, 243, 239, 17, 196, 251, 133, 30, 56, 89, 220, 74, 144, 209, 105, 150, 125,
                139, 44, 132, 127, 191, 13, 64, 39, 240, 246, 10, 240, 124, 104
            ]
        );
    }

    #[test]
    fn test_stedy_rng_next_u32() {
        let mut state = StedyRngState { opaque: [0u8; 132] };
        let state = &mut state as *mut _;
        let seed = [0u8; 128];
        unsafe { stedy_rng_from(seed.as_ptr(), state) };
        let result = unsafe { stedy_rng_next_u32(state) };
        assert_eq!(result, 4025718617);
    }

    #[test]
    fn test_stedy_rng_next_u64() {
        let mut state = StedyRngState { opaque: [0u8; 132] };
        let state = &mut state as *mut _;
        let seed = [0u8; 128];
        unsafe { stedy_rng_from(seed.as_ptr(), state) };
        let result = unsafe { stedy_rng_next_u64(state) };
        assert_eq!(result, 9654525807517996889);
    }
}
