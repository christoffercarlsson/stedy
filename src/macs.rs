#[cfg(feature = "aes")]
mod ghash;
mod hmac;
mod poly1305;

pub(crate) use poly1305::*;

#[cfg(feature = "aes")]
pub(crate) use ghash::*;

pub use hmac::*;

#[cfg(feature = "hazmat")]
pub use poly1305::*;

#[cfg(all(feature = "aes", feature = "hazmat"))]
pub use ghash::*;
