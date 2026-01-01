use {crate::wipe::wipe, core::slice};

#[no_mangle]
pub unsafe extern "C" fn stedy_wipe(data: *mut u8, size: usize) {
    let data = slice::from_raw_parts_mut(data, size);
    wipe(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_wipe() {
        let mut data = [
            80, 140, 94, 140, 50, 124, 20, 226, 225, 167, 43, 163, 78, 235, 69, 47, 55, 69, 139,
            32, 158, 214, 58, 41, 77, 153, 155, 76, 134, 103, 89, 130,
        ];
        unsafe { stedy_wipe(data.as_mut_ptr(), data.len()) };
        assert_eq!(data, [0u8; 32]);
    }
}
