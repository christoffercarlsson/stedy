#![no_main]

use {
    libfuzzer_sys::fuzz_target,
    stedy::{
        key_exchange::{P256, P384, P521, X25519},
        traits::{ByteArray, KeyExchange},
    },
};

fn exchange<X: KeyExchange>(data: &[u8]) {
    if data.len() < X::PrivateKey::SIZE + X::PublicKey::SIZE {
        return;
    }
    let (private_key, public_key) = data.split_at(X::PrivateKey::SIZE);
    let private_key = X::PrivateKey::try_from_slice(private_key).unwrap();
    let public_key = X::PublicKey::try_from_slice(&public_key[..X::PublicKey::SIZE]).unwrap();
    if let Ok(derived) = X::public_key(&private_key) {
        let _ = X::key_exchange(&private_key, &derived);
    }
    let _ = X::key_exchange(&private_key, &public_key);
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, data)) = data.split_first() else {
        return;
    };
    match selector % 4 {
        0 => exchange::<X25519>(data),
        1 => exchange::<P256>(data),
        2 => exchange::<P384>(data),
        _ => exchange::<P521>(data),
    }
});
