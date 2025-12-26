use {
    crate::{
        chacha20poly1305::{
            chacha20poly1305_decrypt, chacha20poly1305_encrypt, chacha20poly1305_generate_key,
            chacha20poly1305_increment_nonce, xchacha20poly1305_decrypt, xchacha20poly1305_encrypt,
            xchacha20poly1305_generate_key, xchacha20poly1305_generate_nonce,
            xchacha20poly1305_increment_nonce,
        },
        rng::Rng,
    },
    core::{ptr, slice},
};

#[no_mangle]
pub unsafe extern "C" fn stedy_chacha20poly1305_encrypt(
    key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_size: usize,
    message: *mut u8,
    message_size: usize,
    tag: *mut u8,
) {
    let key: &[u8; 32] = slice::from_raw_parts(key, 32).try_into().unwrap();
    let nonce: &[u8; 12] = slice::from_raw_parts(nonce, 12).try_into().unwrap();
    let aad = if aad.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(aad, aad_size))
    };
    let message = slice::from_raw_parts_mut(message, message_size);
    let _tag = chacha20poly1305_encrypt(key, nonce, aad, message);
    ptr::copy(_tag.as_ptr(), tag, 16);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_chacha20poly1305_decrypt(
    key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_size: usize,
    message: *mut u8,
    message_size: usize,
    tag: *const u8,
) -> bool {
    let key: &[u8; 32] = slice::from_raw_parts(key, 32).try_into().unwrap();
    let nonce: &[u8; 12] = slice::from_raw_parts(nonce, 12).try_into().unwrap();
    let aad = if aad.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(aad, aad_size))
    };
    let message = slice::from_raw_parts_mut(message, message_size);
    let tag: &[u8; 16] = slice::from_raw_parts(tag, 16).try_into().unwrap();
    chacha20poly1305_decrypt(key, nonce, aad, message, tag)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_chacha20poly1305_generate_key(key: *mut u8) {
    let mut rng = Rng::seed().unwrap();
    let _key = chacha20poly1305_generate_key(&mut rng);
    ptr::copy(_key.as_ptr(), key, 32);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_chacha20poly1305_increment_nonce(nonce: *mut u8) -> bool {
    let nonce: &mut [u8; 12] = slice::from_raw_parts_mut(nonce, 12).try_into().unwrap();
    chacha20poly1305_increment_nonce(nonce)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_xchacha20poly1305_encrypt(
    key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_size: usize,
    message: *mut u8,
    message_size: usize,
    tag: *mut u8,
) {
    let key: &[u8; 32] = slice::from_raw_parts(key, 32).try_into().unwrap();
    let nonce: &[u8; 24] = slice::from_raw_parts(nonce, 24).try_into().unwrap();
    let aad = if aad.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(aad, aad_size))
    };
    let message = slice::from_raw_parts_mut(message, message_size);
    let _tag = xchacha20poly1305_encrypt(key, nonce, aad, message);
    ptr::copy(_tag.as_ptr(), tag, 16);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_xchacha20poly1305_decrypt(
    key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_size: usize,
    message: *mut u8,
    message_size: usize,
    tag: *const u8,
) -> bool {
    let key: &[u8; 32] = slice::from_raw_parts(key, 32).try_into().unwrap();
    let nonce: &[u8; 24] = slice::from_raw_parts(nonce, 24).try_into().unwrap();
    let aad = if aad.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(aad, aad_size))
    };
    let message = slice::from_raw_parts_mut(message, message_size);
    let tag: &[u8; 16] = slice::from_raw_parts(tag, 16).try_into().unwrap();
    xchacha20poly1305_decrypt(key, nonce, aad, message, tag)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_xchacha20poly1305_generate_key(key: *mut u8) {
    let mut rng = Rng::seed().unwrap();
    let _key = xchacha20poly1305_generate_key(&mut rng);
    ptr::copy(_key.as_ptr(), key, 32);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_xchacha20poly1305_increment_nonce(nonce: *mut u8) -> bool {
    let nonce: &mut [u8; 24] = slice::from_raw_parts_mut(nonce, 24).try_into().unwrap();
    xchacha20poly1305_increment_nonce(nonce)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_xchacha20poly1305_generate_nonce(nonce: *mut u8) {
    let mut rng = Rng::seed().unwrap();
    let _nonce = xchacha20poly1305_generate_nonce(&mut rng);
    ptr::copy(_nonce.as_ptr(), nonce, 24);
}
