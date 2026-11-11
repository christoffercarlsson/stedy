mod aead;
#[cfg(feature = "aes")]
mod aes_gcm;
mod chacha20poly1305;
mod xsalsa20poly1305;

#[cfg(not(feature = "hazmat"))]
pub(crate) use aead::Aead;

pub use {chacha20poly1305::*, xsalsa20poly1305::*};

#[cfg(feature = "hazmat")]
pub use aead::Aead;

#[cfg(feature = "aes")]
pub use aes_gcm::*;
