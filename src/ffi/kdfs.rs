use {
    crate::{
        hashes::{Sha256, Sha512},
        kdfs::{pbkdf2, Hkdf},
        macs::Hmac,
    },
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

#[no_mangle]
pub unsafe extern "C" fn stedy_pbkdf2_hmac_sha256(
    password: *const u8,
    password_size: usize,
    salt: *const u8,
    salt_size: usize,
    iterations: usize,
    output: *mut u8,
    output_size: usize,
) {
    let password = slice::from_raw_parts(password, password_size);
    let salt = slice::from_raw_parts(salt, salt_size);
    let output = slice::from_raw_parts_mut(output, output_size);
    pbkdf2::<Hmac<Sha256>>(password, salt, iterations, output);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_pbkdf2_hmac_sha512(
    password: *const u8,
    password_size: usize,
    salt: *const u8,
    salt_size: usize,
    iterations: usize,
    output: *mut u8,
    output_size: usize,
) {
    let password = slice::from_raw_parts(password, password_size);
    let salt = slice::from_raw_parts(salt, salt_size);
    let output = slice::from_raw_parts_mut(output, output_size);
    pbkdf2::<Hmac<Sha512>>(password, salt, iterations, output);
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

    #[test]
    fn test_stedy_pbkdf2_hmac_sha256() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 4096;
        let mut output = [0u8; 32];
        unsafe {
            stedy_pbkdf2_hmac_sha256(
                password.as_ptr(),
                password.len(),
                salt.as_ptr(),
                salt.len(),
                iterations,
                output.as_mut_ptr(),
                output.len(),
            )
        };
        assert_eq!(
            output,
            [
                197, 228, 120, 213, 146, 136, 200, 65, 170, 83, 13, 182, 132, 92, 76, 141, 150, 40,
                147, 160, 1, 206, 78, 17, 164, 150, 56, 115, 170, 152, 19, 74
            ]
        );
    }

    #[test]
    fn test_stedy_pbkdf2_hmac_sha512() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 4096;
        let mut output = [0u8; 64];
        unsafe {
            stedy_pbkdf2_hmac_sha512(
                password.as_ptr(),
                password.len(),
                salt.as_ptr(),
                salt.len(),
                iterations,
                output.as_mut_ptr(),
                output.len(),
            )
        };
        assert_eq!(
            output,
            [
                209, 151, 177, 179, 61, 176, 20, 62, 1, 139, 18, 243, 209, 209, 71, 158, 108, 222,
                189, 204, 151, 197, 192, 248, 127, 105, 2, 224, 114, 244, 87, 181, 20, 63, 48, 96,
                38, 65, 179, 213, 92, 211, 53, 152, 140, 179, 107, 132, 55, 96, 96, 236, 213, 50,
                224, 57, 183, 66, 162, 57, 67, 74, 242, 213
            ]
        );
    }
}
