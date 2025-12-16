use {
    crate::api::{hkdf_sha256, hkdf_sha512},
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
    hkdf_sha256(ikm, salt, info, okm)
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
    hkdf_sha512(ikm, salt, info, okm)
}
