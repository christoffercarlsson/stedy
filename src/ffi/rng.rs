use {
    crate::api::Rng,
    core::{mem::size_of, ptr, slice},
};

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_init(state: *mut u8, seed: *const u8) {
    let seed: &[u8; 32] = slice::from_raw_parts(seed, 32).try_into().unwrap();
    let dest = state as *mut Rng;
    let src = Rng::from(seed);
    ptr::write(dest, src);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_fill(state: *mut u8, bytes: *mut u8, size: usize) {
    let state = state as *mut Rng;
    let bytes = slice::from_raw_parts_mut(bytes, size);
    ptr::read(state).fill(bytes);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_next_u32(state: *mut u8) -> u32 {
    let state = state as *mut Rng;
    ptr::read(state).next_u32()
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_next_u64(state: *mut u8) -> u64 {
    let state = state as *mut Rng;
    ptr::read(state).next_u64()
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_state_size() -> usize {
    size_of::<Rng>()
}
