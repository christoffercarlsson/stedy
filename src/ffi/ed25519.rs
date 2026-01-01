use {
    crate::{
        ed25519::{ed25519_generate_key_pair, ed25519_public_key, ed25519_sign, ed25519_verify},
        rng::Rng,
    },
    core::{ptr, slice},
};

#[no_mangle]
pub unsafe extern "C" fn stedy_ed25519_generate_key_pair(
    private_key: *mut u8,
    public_key: *mut u8,
) {
    let mut rng = Rng::seed().unwrap();
    let (_private_key, _public_key) = ed25519_generate_key_pair(&mut rng);
    ptr::copy(_private_key.as_ptr(), private_key, 32);
    ptr::copy(_public_key.as_ptr(), public_key, 32);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_ed25519_public_key(private_key: *const u8, public_key: *mut u8) {
    let private_key: &[u8; 32] = slice::from_raw_parts(private_key, 32).try_into().unwrap();
    let _public_key = ed25519_public_key(private_key);
    ptr::copy(_public_key.as_ptr(), public_key, 32);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_ed25519_sign(
    private_key: *const u8,
    message: *const u8,
    message_size: usize,
    signature: *mut u8,
) {
    let private_key: &[u8; 32] = slice::from_raw_parts(private_key, 32).try_into().unwrap();
    let message = slice::from_raw_parts(message, message_size);
    let _signature = ed25519_sign(private_key, message);
    ptr::copy(_signature.as_ptr(), signature, 64);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_ed25519_verify(
    message: *const u8,
    message_size: usize,
    public_key: *const u8,
    signature: *const u8,
) -> bool {
    let message = slice::from_raw_parts(message, message_size);
    let public_key: &[u8; 32] = slice::from_raw_parts(public_key, 32).try_into().unwrap();
    let signature: &[u8; 64] = slice::from_raw_parts(signature, 64).try_into().unwrap();
    ed25519_verify(message, &public_key, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stedy_ed25519_generate_key_pair() {
        let mut private_key = [0u8; 32];
        let mut public_key = [0u8; 32];
        unsafe {
            stedy_ed25519_generate_key_pair(private_key.as_mut_ptr(), public_key.as_mut_ptr())
        };
        assert_ne!(private_key, [0u8; 32]);
        assert_ne!(public_key, [0u8; 32]);
        assert_ne!(
            private_key,
            [
                164, 57, 211, 237, 179, 104, 1, 234, 36, 204, 6, 111, 41, 227, 2, 30, 141, 242,
                229, 229, 5, 91, 53, 238, 8, 215, 139, 233, 41, 127, 255, 205
            ]
        );
        assert_ne!(
            public_key,
            [
                185, 175, 67, 174, 182, 228, 51, 132, 174, 211, 127, 232, 89, 49, 129, 38, 12, 69,
                16, 12, 109, 7, 176, 36, 247, 153, 77, 167, 38, 229, 59, 121
            ]
        );
    }

    #[test]
    fn test_stedy_ed25519() {
        let private_key = [
            157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73, 197,
            105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
        ];
        let public_key_ref = [
            215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
        ];
        let message = [];
        let signature_ref = [
            229, 86, 67, 0, 195, 96, 172, 114, 144, 134, 226, 204, 128, 110, 130, 138, 132, 135,
            127, 30, 184, 229, 217, 116, 216, 115, 224, 101, 34, 73, 1, 85, 95, 184, 130, 21, 144,
            163, 59, 172, 198, 30, 57, 112, 28, 249, 180, 107, 210, 91, 245, 240, 89, 91, 190, 36,
            101, 81, 65, 67, 142, 122, 16, 11,
        ];
        let mut public_key = [0u8; 32];
        unsafe { stedy_ed25519_public_key(private_key.as_ptr(), public_key.as_mut_ptr()) };
        assert_eq!(public_key, public_key_ref);
        let mut signature = [0u8; 64];
        unsafe {
            stedy_ed25519_sign(
                private_key.as_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
            )
        };
        assert_eq!(signature, signature_ref);
        let verified = unsafe {
            stedy_ed25519_verify(
                message.as_ptr(),
                message.len(),
                public_key.as_ptr(),
                signature.as_ptr(),
            )
        };
        assert!(verified);
    }
}
