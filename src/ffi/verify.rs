use {crate::verify::verify, core::slice};

#[no_mangle]
pub unsafe extern "C" fn stedy_verify(a: *const u8, b: *const u8, size: usize) -> bool {
    let a = slice::from_raw_parts(a, size);
    let b = slice::from_raw_parts(b, size);
    verify(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_verify() {
        let a = [0; 16];
        let b = [0; 16];
        let c = [1; 16];
        let verified = unsafe { stedy_verify(a.as_ptr(), b.as_ptr(), 16) };
        assert_eq!(verified, true);
        let verified = unsafe { stedy_verify(a.as_ptr(), c.as_ptr(), 16) };
        assert_eq!(verified, false);
        let verified = unsafe { stedy_verify(b.as_ptr(), c.as_ptr(), 16) };
        assert_eq!(verified, false);
    }
}
