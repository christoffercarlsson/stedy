use {
    crate::api::{pbkdf2_hmac_sha256, pbkdf2_hmac_sha512},
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
    pbkdf2_hmac_sha256(password, salt, iterations, output);
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
    pbkdf2_hmac_sha512(password, salt, iterations, output);
}
