#![doc = include_str!("../docs/traits/README.md")]

mod external;
mod internal;

pub use external::{Aead, ByteArray, HashFunction, Kdf, Kem, KeyExchange, Mac, SignatureScheme};

#[cfg(feature = "hazmat")]
pub use external::*;

pub(crate) use internal::*;

#[cfg(not(feature = "hazmat"))]
pub(crate) use external::*;
