use {
    crate::{hkdf::Hkdf, sha256::Sha256, sha512::Sha512},
    core::slice,
};

#[no_mangle]
pub unsafe extern "C" fn stedy_hkdf_sha256(
    ikm: *const u8,
    ikm_size: usize,
    salt: *const u8,
    salt_size: usize,
    info: *const u8,
    info_size: usize,
    okm: *mut u8,
    okm_size: usize,
) {
    let ikm = slice::from_raw_parts(ikm, ikm_size);
    let salt = if salt.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(salt, salt_size))
    };
    let info = if info.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(info, info_size))
    };
    let okm = slice::from_raw_parts_mut(okm, okm_size);
    Hkdf::<Sha256>::hkdf(ikm, salt, info, okm)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_hkdf_sha512(
    ikm: *const u8,
    ikm_size: usize,
    salt: *const u8,
    salt_size: usize,
    info: *const u8,
    info_size: usize,
    okm: *mut u8,
    okm_size: usize,
) {
    let ikm = slice::from_raw_parts(ikm, ikm_size);
    let salt = if salt.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(salt, salt_size))
    };
    let info = if info.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(info, info_size))
    };
    let okm = slice::from_raw_parts_mut(okm, okm_size);
    Hkdf::<Sha512>::hkdf(ikm, salt, info, okm)
}

#[cfg(test)]
mod tests {
    use {super::*, core::ptr};

    #[test]
    fn test_stedy_hkdf_sha256() {
        let ikm = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let salt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let info = [240, 241, 242, 243, 244, 245, 246, 247, 248, 249];
        let mut okm = [0; 42];
        unsafe {
            stedy_hkdf_sha256(
                ikm.as_ptr(),
                ikm.len(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
                okm.as_mut_ptr(),
                okm.len(),
            )
        };
        assert_eq!(
            okm,
            [
                60, 178, 95, 37, 250, 172, 213, 122, 144, 67, 79, 100, 208, 54, 47, 42, 45, 45, 10,
                144, 207, 26, 90, 76, 93, 176, 45, 86, 236, 196, 197, 191, 52, 0, 114, 8, 213, 184,
                135, 24, 88, 101,
            ]
        );
    }

    #[test]
    fn test_stedy_hkdf_sha256_no_salt() {
        let ikm = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let mut okm = [0; 42];
        unsafe {
            stedy_hkdf_sha256(
                ikm.as_ptr(),
                ikm.len(),
                ptr::null(),
                0,
                ptr::null(),
                0,
                okm.as_mut_ptr(),
                okm.len(),
            )
        };
        assert_eq!(
            okm,
            [
                141, 164, 231, 117, 165, 99, 193, 143, 113, 95, 128, 42, 6, 60, 90, 49, 184, 161,
                31, 92, 94, 225, 135, 158, 195, 69, 78, 95, 60, 115, 141, 45, 157, 32, 19, 149,
                250, 164, 182, 26, 150, 200,
            ]
        );
    }

    #[test]
    fn test_stedy_hkdf_sha512() {
        let ikm = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let salt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let info = [240, 241, 242, 243, 244, 245, 246, 247, 248, 249];
        let mut okm = [0; 42];
        unsafe {
            stedy_hkdf_sha512(
                ikm.as_ptr(),
                ikm.len(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
                okm.as_mut_ptr(),
                okm.len(),
            )
        };
        assert_eq!(
            okm,
            [
                131, 35, 144, 8, 108, 218, 113, 251, 71, 98, 91, 181, 206, 177, 104, 228, 200, 226,
                106, 26, 22, 237, 52, 217, 252, 127, 233, 44, 20, 129, 87, 147, 56, 218, 54, 44,
                184, 217, 249, 37, 215, 203,
            ]
        );
    }

    #[test]
    fn test_stedy_hkdf_sha512_no_salt() {
        let ikm = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let mut okm = [0; 42];
        unsafe {
            stedy_hkdf_sha512(
                ikm.as_ptr(),
                ikm.len(),
                ptr::null(),
                0,
                ptr::null(),
                0,
                okm.as_mut_ptr(),
                okm.len(),
            )
        };
        assert_eq!(
            okm,
            [
                245, 250, 2, 177, 130, 152, 167, 42, 140, 35, 137, 138, 135, 3, 71, 44, 110, 177,
                121, 220, 32, 76, 3, 66, 92, 151, 14, 59, 22, 75, 249, 15, 255, 34, 208, 72, 54,
                208, 226, 52, 59, 172,
            ]
        );
    }
}
