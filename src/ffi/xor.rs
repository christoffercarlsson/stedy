use {crate::xor::xor, core::slice};

#[no_mangle]
pub unsafe extern "C" fn stedy_xor(x: *mut u8, x_size: usize, y: *const u8, y_size: usize) {
    let x = slice::from_raw_parts_mut(x, x_size);
    let y = slice::from_raw_parts(y, y_size);
    xor(x, y);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_xor() {
        let mut x = [0, 186, 88, 78, 141, 119, 241, 56, 159, 38, 140, 216];
        let y = [0, 129, 129, 138, 254, 243, 236, 227, 82, 207, 10, 195];
        let z = [0, 59, 217, 196, 115, 132, 29, 219, 205, 233, 134, 27];
        unsafe { stedy_xor(x.as_mut_ptr(), x.len(), y.as_ptr(), y.len()) };
        assert_eq!(x, z);
    }

    #[test]
    fn test_stedy_xor_different_sizes() {
        let mut x = [0, 186, 88, 78, 141, 119, 241, 56, 159, 38, 140, 216];
        let y = [0, 129, 129, 138, 254, 243, 236, 227];
        let z = [0, 59, 217, 196, 115, 132, 29, 219, 159, 38, 140, 216];
        unsafe { stedy_xor(x.as_mut_ptr(), x.len(), y.as_ptr(), y.len()) };
        assert_eq!(x, z);
    }
}
