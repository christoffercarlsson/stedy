#![no_std]

#[cfg(feature = "getrandom")]
extern crate getrandom;

mod block;
mod chacha;
mod chacha20poly1305;
mod field;
mod hkdf_sha256;
mod hkdf_sha512;
mod hmac_sha256;
mod hmac_sha512;
mod poly1305;
mod rng;
mod sha256;
mod sha512;
mod verify;
mod x25519;
mod xor;

#[derive(Debug)]
pub enum Error {
    Entropy,
    Decryption,
    InvalidInput,
    Verification,
}

pub use crate::{
    chacha20poly1305::{chacha20poly1305_decrypt, chacha20poly1305_encrypt},
    hkdf_sha256::hkdf_sha256,
    hkdf_sha512::hkdf_sha512,
    hmac_sha256::{hmac_sha256, hmac_sha256_verify, HmacSha256},
    hmac_sha512::{hmac_sha512, hmac_sha512_verify, HmacSha512},
    rng::Rng,
    sha256::{sha256, Sha256},
    sha512::{sha512, Sha512},
    x25519::{x25519_key_exchange, x25519_public_key},
    xor::xor,
};
