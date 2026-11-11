#[cfg(feature = "aes")]
mod aes;
mod chacha20;
mod salsa20;

pub use {chacha20::*, salsa20::*};

#[cfg(feature = "aes")]
pub(crate) use aes::multiply;

#[cfg(feature = "aes")]
pub use aes::{Aes128Ctr, Aes256Ctr, AesCtr};
