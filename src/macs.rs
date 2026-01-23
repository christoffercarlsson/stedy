mod hmac;
mod poly1305;

#[allow(unused_imports)]
pub(crate) use poly1305::*;

pub use hmac::*;

#[cfg(feature = "hazmat")]
pub use poly1305::*;
