#[cfg(feature = "aes")]
mod ghash;
mod hmac;
mod poly1305;
mod siphash;

#[cfg(not(feature = "hazmat"))]
pub(crate) use poly1305::*;

#[cfg(all(feature = "aes", not(feature = "hazmat")))]
pub(crate) use ghash::*;

pub use {hmac::*, siphash::*};

#[cfg(feature = "hazmat")]
pub use poly1305::*;

#[cfg(all(feature = "aes", feature = "hazmat"))]
pub use ghash::*;
