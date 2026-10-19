mod external;
mod internal;

pub use external::ByteArray;

#[cfg(feature = "hazmat")]
pub use external::*;

pub(crate) use internal::*;

#[cfg(not(feature = "hazmat"))]
pub(crate) use external::*;
