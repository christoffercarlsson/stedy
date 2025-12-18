#![no_std]

#[cfg(feature = "getrandom")]
extern crate getrandom;

mod aead;
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

pub use crate::{
    blake2b::*,
    blake2s::*,
    chacha20poly1305::*,
    ed25519::*,
    hkdf::*,
    hmac::*,
    pad::*,
    pbkdf2::*,
    rng::*,
    sha256::*,
    sha512::*,
    traits::{Csprng, SeedableCsprng},
    verify::*,
    wipe::*,
    x25519::*,
    xor::*,
};

#[cfg(feature = "ffi")]
pub use crate::ffi::*;
