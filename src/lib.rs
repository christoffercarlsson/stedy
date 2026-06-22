#![no_std]
#![deny(clippy::unwrap_used)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod aeads;
#[cfg(not(feature = "hazmat"))]
mod ciphers;
#[cfg(feature = "hazmat")]
pub mod ciphers;
pub mod csprngs;
#[cfg(not(feature = "hazmat"))]
mod elliptic_curves;
#[cfg(feature = "hazmat")]
pub mod elliptic_curves;
pub mod encoding;
pub mod hashes;
pub mod kdfs;
pub mod key_exchange;
pub mod macs;
#[cfg(feature = "secret_sharing")]
pub mod secret_sharing;
pub mod signatures;
pub mod traits;
pub mod utils;
