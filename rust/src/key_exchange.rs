use alloc::borrow::ToOwned;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};

use crate::crypto_box::{x25519_get_private_key, X25519KeyPair, X25519PublicKey};

pub const X25519_SHARED_SECRET_SIZE: usize = 32;

pub type X25519SharedSecret = [u8; X25519_SHARED_SECRET_SIZE];

pub fn x25519_key_exchange(
    our_key_pair: &X25519KeyPair,
    their_public_key: &X25519PublicKey,
) -> X25519SharedSecret {
    let static_secret = StaticSecret::from(x25519_get_private_key(our_key_pair));
    let public_key = DalekPublicKey::from(their_public_key.to_owned());
    let mut shared_secret: X25519SharedSecret = [0; X25519_SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(static_secret.diffie_hellman(&public_key).as_bytes());
    shared_secret
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use super::*;
    use crate::crypto_box::{x25519_generate_key_pair, x25519_get_public_key};
    use rand::rngs::OsRng;

    #[test]
    fn test_x25519_key_exchange() {
        let alice_key_pair = x25519_generate_key_pair(OsRng);
        let bob_key_pair = x25519_generate_key_pair(OsRng);
        let alice_public_key = x25519_get_public_key(&alice_key_pair);
        let bob_public_key = x25519_get_public_key(&bob_key_pair);
        let a = x25519_key_exchange(&alice_key_pair, &bob_public_key);
        let b = x25519_key_exchange(&bob_key_pair, &alice_public_key);
        assert_ne!(a, [0; X25519_SHARED_SECRET_SIZE]);
        assert_eq!(a, b);
    }
}
