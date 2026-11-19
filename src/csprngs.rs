#![doc = include_str!("../docs/csprngs/README.md")]

#[cfg(feature = "aes")]
mod aes_ctr_rng;
mod chacha20_rng;
#[cfg(feature = "hazmat")]
mod fixed_rng;
mod hmac_drbg;
mod stream_cipher_rng;

pub(crate) use stream_cipher_rng::StreamCipherRng;

pub use {chacha20_rng::*, hmac_drbg::*};

#[cfg(feature = "aes")]
pub use aes_ctr_rng::*;

#[cfg(feature = "hazmat")]
#[doc(hidden)]
pub use fixed_rng::FixedRng;
