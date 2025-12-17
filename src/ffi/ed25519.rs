use {
    crate::{
        ed25519::{ed25519_generate_key_pair, ed25519_public_key, ed25519_sign, ed25519_verify},
        rng::Rng,
    },
    core::{ptr, slice},
};

#[no_mangle]
pub unsafe extern "C" fn stedy_ed25519_generate_key_pair(
    seed: *const u8,
    private_key: *mut u8,
    public_key: *mut u8,
) {
    let seed: &[u8; 32] = slice::from_raw_parts(seed, 32).try_into().unwrap();
    let mut rng = Rng::from(seed);
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
