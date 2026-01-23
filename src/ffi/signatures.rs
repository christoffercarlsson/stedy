use {
    crate::{csprngs::Rng, ffi::csprngs::StedyRngState, signatures::Ed25519},
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
    let _public_key = Ed25519::public_key(private_key);
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
    Ed25519::verify(message, public_key, signature)
}

#[cfg(test)]
mod tests {
    use {super::*, crate::ffi::csprngs::stedy_rng_from};

    #[test]
    fn test_stedy_ed25519_generate_key_pair() {
        let mut rng = StedyRngState { opaque: [0u8; 132] };
        let rng = &mut rng as *mut _;
        let seed = [0u8; 128];
        unsafe { stedy_rng_from(seed.as_ptr(), rng) };
        let mut private_key = [0u8; 32];
        let mut public_key = [0u8; 32];
        unsafe {
            stedy_ed25519_generate_key_pair(rng, private_key.as_mut_ptr(), public_key.as_mut_ptr())
        };
        assert_eq!(
            private_key,
            [
                89, 151, 243, 239, 17, 196, 251, 133, 30, 56, 89, 220, 74, 144, 209, 105, 150, 125,
                139, 44, 132, 127, 191, 13, 64, 39, 240, 246, 10, 240, 124, 104
            ]
        );
        assert_eq!(
            public_key,
            [
                83, 121, 189, 164, 155, 254, 164, 43, 251, 141, 163, 57, 137, 129, 179, 216, 113,
                235, 45, 249, 212, 221, 167, 255, 214, 81, 113, 170, 238, 60, 11, 60
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
