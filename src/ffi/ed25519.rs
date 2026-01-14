use {
    crate::{csprng::Rng, ed25519::Ed25519, ffi::rng::StedyRngState},
    core::{ptr, slice},
};

#[no_mangle]
pub unsafe extern "C" fn stedy_ed25519_generate_key_pair(
    rng: *mut StedyRngState,
    private_key: *mut u8,
    public_key: *mut u8,
) {
    let rng = &mut *(rng as *mut Rng);
    let (_private_key, _public_key) = Ed25519::generate_key_pair(rng);
    ptr::copy(_private_key.as_ptr(), private_key, 32);
    ptr::copy(_public_key.as_ptr(), public_key, 32);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_ed25519_public_key(private_key: *const u8, public_key: *mut u8) {
    let private_key: &[u8; 32] = slice::from_raw_parts(private_key, 32).try_into().unwrap();
    let _public_key = Ed25519::get_public_key(private_key);
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
    let _signature = Ed25519::sign(private_key, message);
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
    Ed25519::verify(message, &public_key, &signature)
}

#[cfg(test)]
mod tests {
    use {super::*, crate::ffi::rng::stedy_rng_seed};

    #[test]
    fn test_stedy_ed25519_generate_key_pair() {
        let mut rng = StedyRngState { opaque: [0u8; 132] };
        let rng = &mut rng as *mut _;
        let seed = [0u8; 96];
        unsafe { stedy_rng_seed(seed.as_ptr(), 96, rng) };
        let mut private_key = [0u8; 32];
        let mut public_key = [0u8; 32];
        unsafe {
            stedy_ed25519_generate_key_pair(rng, private_key.as_mut_ptr(), public_key.as_mut_ptr())
        };
        assert_eq!(
            private_key,
            [
                189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102,
                238, 246, 149, 42, 27, 28, 74, 169, 187, 175, 23, 175, 195, 58, 204
            ]
        );
        assert_eq!(
            public_key,
            [
                37, 198, 137, 66, 34, 61, 206, 212, 186, 147, 185, 57, 197, 10, 163, 190, 60, 13,
                197, 37, 80, 198, 219, 145, 132, 79, 238, 73, 4, 232, 83, 163
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
