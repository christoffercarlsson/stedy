use {crate::wipe::wipe, core::slice};

#[no_mangle]
pub unsafe extern "C" fn stedy_wipe(data: *mut u8, size: usize) {
    let data = slice::from_raw_parts_mut(data, size);
    wipe(data);
}
