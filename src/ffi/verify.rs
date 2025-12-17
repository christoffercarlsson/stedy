use {crate::verify::verify, core::slice};

#[no_mangle]
pub unsafe extern "C" fn stedy_verify(a: *const u8, b: *const u8, size: usize) -> bool {
    let a = slice::from_raw_parts(a, size);
    let b = slice::from_raw_parts(b, size);
    verify(a, b)
}
