use {
    crate::{
        chacha20poly1305::{
            chacha20poly1305_decrypt, chacha20poly1305_encrypt, chacha20poly1305_generate_key,
            chacha20poly1305_increment_nonce, xchacha20poly1305_decrypt, xchacha20poly1305_encrypt,
            xchacha20poly1305_generate_key, xchacha20poly1305_generate_nonce,
            xchacha20poly1305_increment_nonce,
        },
        csprng::Rng,
        ffi::rng::StedyRngState,
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
pub unsafe extern "C" fn stedy_chacha20poly1305_generate_key(
    rng: *mut StedyRngState,
    key: *mut u8,
) {
    let rng = &mut *(rng as *mut Rng);
    let _key = chacha20poly1305_generate_key(rng);
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
pub unsafe extern "C" fn stedy_xchacha20poly1305_generate_key(
    rng: *mut StedyRngState,
    key: *mut u8,
) {
    let rng = &mut *(rng as *mut Rng);
    let _key = xchacha20poly1305_generate_key(rng);
    ptr::copy(_key.as_ptr(), key, 32);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_xchacha20poly1305_increment_nonce(nonce: *mut u8) -> bool {
    let nonce: &mut [u8; 24] = slice::from_raw_parts_mut(nonce, 24).try_into().unwrap();
    xchacha20poly1305_increment_nonce(nonce)
}

#[no_mangle]
pub unsafe extern "C" fn stedy_xchacha20poly1305_generate_nonce(
    rng: *mut StedyRngState,
    nonce: *mut u8,
) {
    let rng = &mut *(rng as *mut Rng);
    let _nonce = xchacha20poly1305_generate_nonce(rng);
    ptr::copy(_nonce.as_ptr(), nonce, 24);
}

#[cfg(test)]
mod tests {
    use {super::*, crate::ffi::rng::stedy_rng_seed};

    #[test]
    fn test_stedy_chacha20poly1305() {
        let key = [
            128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144,
            145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
        ];
        let nonce = [7, 0, 0, 0, 64, 65, 66, 67, 68, 69, 70, 71];
        let aad = [80, 81, 82, 83, 192, 193, 194, 195, 196, 197, 198, 199];
        let mut message = [
            76, 97, 100, 105, 101, 115, 32, 97, 110, 100, 32, 71, 101, 110, 116, 108, 101, 109,
            101, 110, 32, 111, 102, 32, 116, 104, 101, 32, 99, 108, 97, 115, 115, 32, 111, 102, 32,
            39, 57, 57, 58, 32, 73, 102, 32, 73, 32, 99, 111, 117, 108, 100, 32, 111, 102, 102,
            101, 114, 32, 121, 111, 117, 32, 111, 110, 108, 121, 32, 111, 110, 101, 32, 116, 105,
            112, 32, 102, 111, 114, 32, 116, 104, 101, 32, 102, 117, 116, 117, 114, 101, 44, 32,
            115, 117, 110, 115, 99, 114, 101, 101, 110, 32, 119, 111, 117, 108, 100, 32, 98, 101,
            32, 105, 116, 46,
        ];
        let mut tag = [0u8; 16];
        unsafe {
            stedy_chacha20poly1305_encrypt(
                key.as_ptr(),
                nonce.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                message.as_mut_ptr(),
                message.len(),
                tag.as_mut_ptr(),
            )
        };
        assert_eq!(
            message,
            [
                211, 26, 141, 52, 100, 142, 96, 219, 123, 134, 175, 188, 83, 239, 126, 194, 164,
                173, 237, 81, 41, 110, 8, 254, 169, 226, 181, 167, 54, 238, 98, 214, 61, 190, 164,
                94, 140, 169, 103, 18, 130, 250, 251, 105, 218, 146, 114, 139, 26, 113, 222, 10,
                158, 6, 11, 41, 5, 214, 165, 182, 126, 205, 59, 54, 146, 221, 189, 127, 45, 119,
                139, 140, 152, 3, 174, 227, 40, 9, 27, 88, 250, 179, 36, 228, 250, 214, 117, 148,
                85, 133, 128, 139, 72, 49, 215, 188, 63, 244, 222, 240, 142, 75, 122, 157, 229,
                118, 210, 101, 134, 206, 198, 75, 97, 22
            ]
        );
        assert_eq!(
            tag,
            [26, 225, 11, 89, 79, 9, 226, 106, 126, 144, 46, 203, 208, 96, 6, 145]
        );
        let verified = unsafe {
            stedy_chacha20poly1305_decrypt(
                key.as_ptr(),
                nonce.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                message.as_mut_ptr(),
                message.len(),
                tag.as_ptr(),
            )
        };
        assert!(verified);
        assert_eq!(
            message,
            [
                76, 97, 100, 105, 101, 115, 32, 97, 110, 100, 32, 71, 101, 110, 116, 108, 101, 109,
                101, 110, 32, 111, 102, 32, 116, 104, 101, 32, 99, 108, 97, 115, 115, 32, 111, 102,
                32, 39, 57, 57, 58, 32, 73, 102, 32, 73, 32, 99, 111, 117, 108, 100, 32, 111, 102,
                102, 101, 114, 32, 121, 111, 117, 32, 111, 110, 108, 121, 32, 111, 110, 101, 32,
                116, 105, 112, 32, 102, 111, 114, 32, 116, 104, 101, 32, 102, 117, 116, 117, 114,
                101, 44, 32, 115, 117, 110, 115, 99, 114, 101, 101, 110, 32, 119, 111, 117, 108,
                100, 32, 98, 101, 32, 105, 116, 46,
            ]
        );
    }

    #[test]
    fn test_stedy_chacha20poly1305_generate_key() {
        let mut rng = StedyRngState { opaque: [0u8; 132] };
        let rng = &mut rng as *mut _;
        let seed = [0u8; 32];
        unsafe { stedy_rng_seed(seed.as_ptr(), rng) };
        let mut key = [0u8; 32];
        unsafe { stedy_chacha20poly1305_generate_key(rng, key.as_mut_ptr()) };
        assert_eq!(
            key,
            [
                164, 57, 211, 237, 179, 104, 1, 234, 36, 204, 6, 111, 41, 227, 2, 30, 141, 242,
                229, 229, 5, 91, 53, 238, 8, 215, 139, 233, 41, 127, 255, 205
            ]
        );
    }

    #[test]
    fn test_stedy_chacha20poly1305_increment_nonce() {
        let mut nonce = [42u8; 12];
        let incremented = unsafe { stedy_chacha20poly1305_increment_nonce(nonce.as_mut_ptr()) };
        assert!(incremented == true);
        assert_eq!(nonce, [42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 43]);
        let mut nonce = [255u8; 12];
        let incremented = unsafe { stedy_chacha20poly1305_increment_nonce(nonce.as_mut_ptr()) };
        assert!(incremented == false);
        assert_eq!(nonce, [0u8; 12]);
    }

    #[test]
    fn test_stedy_xchacha20poly1305() {
        let key = [
            128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144,
            145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
        ];
        let nonce = [
            64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85,
            86, 87,
        ];
        let aad = [80, 81, 82, 83, 192, 193, 194, 195, 196, 197, 198, 199];
        let mut message = [
            76, 97, 100, 105, 101, 115, 32, 97, 110, 100, 32, 71, 101, 110, 116, 108, 101, 109,
            101, 110, 32, 111, 102, 32, 116, 104, 101, 32, 99, 108, 97, 115, 115, 32, 111, 102, 32,
            39, 57, 57, 58, 32, 73, 102, 32, 73, 32, 99, 111, 117, 108, 100, 32, 111, 102, 102,
            101, 114, 32, 121, 111, 117, 32, 111, 110, 108, 121, 32, 111, 110, 101, 32, 116, 105,
            112, 32, 102, 111, 114, 32, 116, 104, 101, 32, 102, 117, 116, 117, 114, 101, 44, 32,
            115, 117, 110, 115, 99, 114, 101, 101, 110, 32, 119, 111, 117, 108, 100, 32, 98, 101,
            32, 105, 116, 46,
        ];
        let mut tag = [0u8; 16];
        unsafe {
            stedy_xchacha20poly1305_encrypt(
                key.as_ptr(),
                nonce.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                message.as_mut_ptr(),
                message.len(),
                tag.as_mut_ptr(),
            )
        };
        assert_eq!(
            message,
            [
                189, 109, 23, 157, 62, 131, 212, 59, 149, 118, 87, 148, 147, 192, 233, 57, 87, 42,
                23, 0, 37, 43, 250, 204, 190, 210, 144, 44, 33, 57, 108, 187, 115, 28, 127, 27, 11,
                74, 166, 68, 11, 243, 168, 47, 78, 218, 126, 57, 174, 100, 198, 112, 140, 84, 194,
                22, 203, 150, 183, 46, 18, 19, 180, 82, 47, 140, 155, 164, 13, 181, 217, 69, 177,
                27, 105, 185, 130, 193, 187, 158, 63, 63, 172, 43, 195, 105, 72, 143, 118, 178, 56,
                53, 101, 211, 255, 249, 33, 249, 102, 76, 151, 99, 125, 169, 118, 136, 18, 246, 21,
                198, 139, 19, 181, 46
            ]
        );
        assert_eq!(
            tag,
            [192, 135, 89, 36, 193, 199, 152, 121, 71, 222, 175, 216, 120, 10, 207, 73]
        );
        let verified = unsafe {
            stedy_xchacha20poly1305_decrypt(
                key.as_ptr(),
                nonce.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                message.as_mut_ptr(),
                message.len(),
                tag.as_ptr(),
            )
        };
        assert!(verified);
        assert_eq!(
            message,
            [
                76, 97, 100, 105, 101, 115, 32, 97, 110, 100, 32, 71, 101, 110, 116, 108, 101, 109,
                101, 110, 32, 111, 102, 32, 116, 104, 101, 32, 99, 108, 97, 115, 115, 32, 111, 102,
                32, 39, 57, 57, 58, 32, 73, 102, 32, 73, 32, 99, 111, 117, 108, 100, 32, 111, 102,
                102, 101, 114, 32, 121, 111, 117, 32, 111, 110, 108, 121, 32, 111, 110, 101, 32,
                116, 105, 112, 32, 102, 111, 114, 32, 116, 104, 101, 32, 102, 117, 116, 117, 114,
                101, 44, 32, 115, 117, 110, 115, 99, 114, 101, 101, 110, 32, 119, 111, 117, 108,
                100, 32, 98, 101, 32, 105, 116, 46,
            ]
        );
    }

    #[test]
    fn test_stedy_xchacha20poly1305_generate_key() {
        let mut rng = StedyRngState { opaque: [0u8; 132] };
        let rng = &mut rng as *mut _;
        let seed = [0u8; 32];
        unsafe { stedy_rng_seed(seed.as_ptr(), rng) };
        let mut key = [0u8; 32];
        unsafe { stedy_xchacha20poly1305_generate_key(rng, key.as_mut_ptr()) };
        assert_eq!(
            key,
            [
                164, 57, 211, 237, 179, 104, 1, 234, 36, 204, 6, 111, 41, 227, 2, 30, 141, 242,
                229, 229, 5, 91, 53, 238, 8, 215, 139, 233, 41, 127, 255, 205
            ]
        );
    }

    #[test]
    fn test_stedy_xchacha20poly1305_generate_nonce() {
        let mut rng = StedyRngState { opaque: [0u8; 132] };
        let rng = &mut rng as *mut _;
        let seed = [0u8; 32];
        unsafe { stedy_rng_seed(seed.as_ptr(), rng) };
        let mut nonce = [0u8; 24];
        unsafe { stedy_xchacha20poly1305_generate_nonce(rng, nonce.as_mut_ptr()) };
        assert_eq!(
            nonce,
            [
                164, 57, 211, 237, 179, 104, 1, 234, 36, 204, 6, 111, 41, 227, 2, 30, 141, 242,
                229, 229, 5, 91, 53, 238
            ]
        );
    }

    #[test]
    fn test_stedy_xchacha20poly1305_increment_nonce() {
        let mut nonce = [0u8; 24];
        let incremented = unsafe { stedy_xchacha20poly1305_increment_nonce(nonce.as_mut_ptr()) };
        assert!(incremented == true);
        assert_eq!(
            nonce,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        let mut nonce = [255u8; 24];
        let incremented = unsafe { stedy_xchacha20poly1305_increment_nonce(nonce.as_mut_ptr()) };
        assert!(incremented == false);
        assert_eq!(nonce, [0u8; 24]);
    }
}
