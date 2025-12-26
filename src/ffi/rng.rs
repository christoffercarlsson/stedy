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
pub unsafe extern "C" fn stedy_rng_fill(state: *mut StedyRngState, bytes: *mut u8, size: usize) {
    let state = state as *mut Rng;
    let bytes = slice::from_raw_parts_mut(bytes, size);
    ptr::read(state).fill(bytes);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_next_u32(state: *mut StedyRngState) -> u32 {
    let state = state as *mut Rng;
    ptr::read(state).next_u32()
}

#[no_mangle]
pub unsafe extern "C" fn stedy_rng_next_u64(state: *mut StedyRngState) -> u64 {
    let state = state as *mut Rng;
    ptr::read(state).next_u64()
}
