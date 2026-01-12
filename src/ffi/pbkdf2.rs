use {
    crate::{hmac::Hmac, pbkdf2::pbkdf2, sha256::Sha256, sha512::Sha512},
    core::slice,
};

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
    use super::*;

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
