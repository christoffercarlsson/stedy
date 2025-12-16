#![no_std]

mod aead;
mod api;
mod blake2b;
mod blake2s;
mod block;
mod chacha;
mod chacha20poly1305;
mod curve25519;
mod ed25519;
#[cfg(feature = "ffi")]
mod ffi;
mod hkdf;
mod hmac;
mod pad;
mod pbkdf2;
mod poly1305;
mod rng;
mod sha1;
mod sha256;
mod sha512;
mod traits;
mod verify;
mod wipe;
mod x25519;
mod xor;

#[cfg(not(feature = "ffi"))]
pub use crate::api::*;

#[cfg(feature = "ffi")]
pub use crate::ffi::*;
