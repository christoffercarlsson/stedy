use {
    crate::{
        csprng::Rng,
        ffi::rng::StedyRngState,
        x25519::{x25519_generate_key_pair, x25519_key_exchange, x25519_public_key},
    },
    core::{ptr, slice},
};

#[no_mangle]
pub unsafe extern "C" fn stedy_x25519_generate_key_pair(
    rng: *mut StedyRngState,
    private_key: *mut u8,
    public_key: *mut u8,
) {
    let rng = &mut *(rng as *mut Rng);
    let (_private_key, _public_key) = x25519_generate_key_pair(rng);
    ptr::copy(_private_key.as_ptr(), private_key, 32);
    ptr::copy(_public_key.as_ptr(), public_key, 32);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_x25519_public_key(private_key: *const u8, public_key: *mut u8) {
    let private_key: &[u8; 32] = slice::from_raw_parts(private_key, 32).try_into().unwrap();
    let _public_key = x25519_public_key(private_key);
    ptr::copy(_public_key.as_ptr(), public_key, 32);
}

#[no_mangle]
pub unsafe extern "C" fn stedy_x25519_key_exchange(
    private_key: *const u8,
    public_key: *const u8,
    shared_secret: *mut u8,
) {
    let private_key: &[u8; 32] = slice::from_raw_parts(private_key, 32).try_into().unwrap();
    let public_key: &[u8; 32] = slice::from_raw_parts(public_key, 32).try_into().unwrap();
    let _shared_secret = x25519_key_exchange(private_key, public_key);
    ptr::copy(_shared_secret.as_ptr(), shared_secret, 32);
}

#[cfg(test)]
mod tests {
    use {super::*, crate::ffi::rng::stedy_rng_seed};

    #[test]
    fn test_stedy_x25519_generate_key_pair() {
        let mut rng = StedyRngState { opaque: [0u8; 132] };
        let rng = &mut rng as *mut _;
        let seed = [0u8; 32];
        unsafe { stedy_rng_seed(seed.as_ptr(), rng) };
        let mut private_key = [0u8; 32];
        let mut public_key = [0u8; 32];
        unsafe {
            stedy_x25519_generate_key_pair(rng, private_key.as_mut_ptr(), public_key.as_mut_ptr())
        };
        assert_eq!(
            private_key,
            [
                164, 57, 211, 237, 179, 104, 1, 234, 36, 204, 6, 111, 41, 227, 2, 30, 141, 242,
                229, 229, 5, 91, 53, 238, 8, 215, 139, 233, 41, 127, 255, 205
            ]
        );
        assert_eq!(
            public_key,
            [
                240, 218, 70, 30, 171, 24, 175, 126, 180, 68, 124, 104, 87, 128, 155, 141, 31, 181,
                213, 146, 237, 163, 35, 113, 239, 169, 232, 235, 1, 185, 245, 81
            ]
        );
    }

    #[test]
    fn test_stedy_x25519_public_key() {
        let private_key = [
            119, 7, 109, 10, 115, 24, 165, 125, 60, 22, 193, 114, 81, 178, 102, 69, 223, 76, 47,
            135, 235, 192, 153, 42, 177, 119, 251, 165, 29, 185, 44, 42,
        ];
        let mut public_key = [0u8; 32];
        unsafe { stedy_x25519_public_key(private_key.as_ptr(), public_key.as_mut_ptr()) };
        assert_eq!(
            public_key,
            [
                133, 32, 240, 9, 137, 48, 167, 84, 116, 139, 125, 220, 180, 62, 247, 90, 13, 191,
                58, 13, 38, 56, 26, 244, 235, 164, 169, 142, 170, 155, 78, 106,
            ]
        );
    }

    #[test]
    fn test_stedy_x25519_key_exchange() {
        let private_key = [
            119, 7, 109, 10, 115, 24, 165, 125, 60, 22, 193, 114, 81, 178, 102, 69, 223, 76, 47,
            135, 235, 192, 153, 42, 177, 119, 251, 165, 29, 185, 44, 42,
        ];
        let public_key = [
            222, 158, 219, 125, 123, 125, 193, 180, 211, 91, 97, 194, 236, 228, 53, 55, 63, 131,
            67, 200, 91, 120, 103, 77, 173, 252, 126, 20, 111, 136, 43, 79,
        ];
        let shared_secret_ref = [
            74, 93, 157, 91, 164, 206, 45, 225, 114, 142, 59, 244, 128, 53, 15, 37, 224, 126, 33,
            201, 71, 209, 158, 51, 118, 240, 155, 60, 30, 22, 23, 66,
        ];
        let mut shared_secret = [0u8; 32];
        unsafe {
            stedy_x25519_key_exchange(
                private_key.as_ptr(),
                public_key.as_ptr(),
                shared_secret.as_mut_ptr(),
            )
        };
        assert_eq!(shared_secret, shared_secret_ref);
    }
}
