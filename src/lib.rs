#![no_std]

mod block;
mod chacha;
mod chacha20poly1305;
mod curve25519;
mod ed25519;
mod hkdf;
mod hmac;
mod poly1305;
mod rng;
mod sha256;
mod sha512;
mod sss;
mod traits;
mod verify;
mod x25519;
mod xor;

pub use crate::{
    chacha20poly1305::{chacha20poly1305_decrypt, chacha20poly1305_encrypt},
    ed25519::{ed25519_generate_key_pair, ed25519_public_key, ed25519_sign, ed25519_verify},
    hkdf::{hkdf_sha256, hkdf_sha512},
    hmac::{
        hmac_sha256, hmac_sha256_verify, hmac_sha512, hmac_sha512_verify, HmacSha256, HmacSha512,
    },
    rng::Rng,
    sha256::{sha256, Sha256},
    sha512::{sha512, Sha512},
    sss::{sss_combine, sss_split},
    x25519::{x25519_generate_key_pair, x25519_key_exchange, x25519_public_key},
    xor::xor,
};
