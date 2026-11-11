#[cfg(feature = "aes")]
mod aes;
#[cfg(all(feature = "aes", feature = "hazmat"))]
mod aes_ctr;
mod chacha20;
mod salsa20;

#[cfg(feature = "aes")]
pub(crate) use aes::{AesCtr, multiply};

pub use {chacha20::*, salsa20::*};

#[cfg(all(feature = "aes", feature = "hazmat"))]
pub use aes_ctr::{Aes128Ctr, Aes256Ctr};
