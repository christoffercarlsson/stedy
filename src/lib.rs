#![no_std]
#![deny(clippy::unwrap_used)]

mod aead;
mod base;
mod blake2b;
mod blake2s;
mod block;
mod chacha;
mod chacha20poly1305;
mod csprng;
mod curve25519;
mod dh;
mod ed25519;
mod eddsa;
mod edwards25519;
#[cfg(feature = "ffi")]
mod ffi;
mod hkdf;
mod hmac;
mod pad;
mod pbkdf2;
mod poly1305;
mod scalar25519;
#[cfg(feature = "hazmat")]
mod sha1;
mod sha256;
mod sha512;
#[cfg(feature = "shamir")]
mod shamir;
mod traits;
mod verify;
mod wipe;
mod x25519;
mod xor;

pub use crate::{
    base::*, blake2b::*, blake2s::*, chacha20poly1305::*, csprng::*, ed25519::*, hkdf::*, hmac::*,
    pad::*, pbkdf2::*, sha256::*, sha512::*, traits::ByteArray, verify::*, wipe::*, x25519::*,
    xor::*,
};

#[cfg(feature = "ffi")]
pub use crate::ffi::*;

#[cfg(feature = "hazmat")]
pub use crate::{
    aead::*, chacha::*, curve25519::*, dh::*, eddsa::*, edwards25519::*, poly1305::*,
    scalar25519::*, sha1::*, traits::*,
};

#[cfg(feature = "shamir")]
pub use crate::shamir::{shamir_combine, shamir_split};

#[cfg(all(feature = "hazmat", feature = "shamir"))]
pub use crate::shamir::*;
