#![no_std]

mod block;
mod chacha;
mod chacha20poly1305;
mod hkdf_sha256;
mod hkdf_sha512;
mod hmac_sha256;
mod hmac_sha512;
mod poly1305;
mod rng;
mod sha256;
mod sha512;
mod verify;
mod xor;

#[derive(Debug)]
pub enum Error {
    Decryption,
    Encryption,
    InvalidInput,
    Verification,
}

pub use chacha20poly1305::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};
pub use hkdf_sha256::hkdf_sha256;
pub use hkdf_sha512::hkdf_sha512;
pub use hmac_sha256::{hmac_sha256, hmac_sha256_verify, HmacSha256};
pub use hmac_sha512::{hmac_sha512, hmac_sha512_verify, HmacSha512};
pub use rng::Rng;
pub use sha256::{sha256, Sha256};
pub use sha512::{sha512, Sha512};
pub use xor::xor;
