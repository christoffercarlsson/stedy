use {
    crate::{
        rng::Rng,
        x25519::{x25519_generate_key_pair, x25519_key_exchange, x25519_public_key},
    },
    core::{ptr, slice},
};

#[no_mangle]
pub unsafe extern "C" fn stedy_x25519_generate_key_pair(
    seed: *const u8,
    private_key: *mut u8,
    public_key: *mut u8,
) {
    let seed: &[u8; 32] = slice::from_raw_parts(seed, 32).try_into().unwrap();
    let mut rng = Rng::from(seed);
    let (_private_key, _public_key) = x25519_generate_key_pair(&mut rng);
    ptr::copy(_private_key.as_ptr(), private_key, 32);
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

#[no_mangle]
pub unsafe extern "C" fn stedy_x25519_public_key(private_key: *const u8, public_key: *mut u8) {
    let private_key: &[u8; 32] = slice::from_raw_parts(private_key, 32).try_into().unwrap();
    let _public_key = x25519_public_key(private_key);
    ptr::copy(_public_key.as_ptr(), public_key, 32);
}
